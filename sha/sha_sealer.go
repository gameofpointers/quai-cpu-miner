package sha

import (
	crand "crypto/rand"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/consensus"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/log"
	"github.com/dominant-strategies/go-quai/params"
)

var (
	errNoMiningWork      = errors.New("no mining work available yet")
	errInvalidSealResult = errors.New("invalid or stale proof-of-work solution")
)

type Sha256pow struct {
	threads int              // Number of threads to mine with (0 = number of cores)
	rand    *rand.Rand       // Random number source to use for mining
	shared  consensus.Engine // Shared miner to use (if any)

	lock   sync.Mutex    // Protects the PoW fields during operation
	update chan struct{} // Notifies a change in the mining threads
	logger *log.Logger   // Logger used by the PoW engine
}

func NewSha256pow(threads int, logger *log.Logger) *Sha256pow {
	return &Sha256pow{
		threads: threads,
		update:  make(chan struct{}),
		logger:  logger,
	}
}

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the header's difficulty requirements.
func (sha256pow *Sha256pow) Seal(header *types.WorkObject, results chan<- *types.WorkObject, stop <-chan struct{}) error {
	// If we're running a shared PoW, delegate sealing to it
	if sha256pow.shared != nil {
		return sha256pow.shared.Seal(header, results, stop)
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})

	sha256pow.lock.Lock()
	threads := sha256pow.threads
	if sha256pow.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			sha256pow.lock.Unlock()
			return err
		}
		sha256pow.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	sha256pow.lock.Unlock()
	if threads == 0 {
		threads = runtime.NumCPU()
	}
	if threads < 0 {
		threads = 0 // Allows disabling local mining without extra logic around local/remote
	}
	var (
		pend   sync.WaitGroup
		locals = make(chan *types.WorkObject)
	)
	for i := 0; i < threads; i++ {
		pend.Add(1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					sha256pow.logger.WithFields(log.Fields{
						"error":      r,
						"stacktrace": string(debug.Stack()),
					}).Error("Go-Quai Panicked")
				}
			}()
			defer pend.Done()
			sha256pow.Mine(header, abort, locals)
		}()
	}
	// Wait until sealing is terminated or a nonce is found
	go func() {
		defer func() {
			if r := recover(); r != nil {
				sha256pow.logger.WithFields(log.Fields{
					"error":      r,
					"stacktrace": string(debug.Stack()),
				}).Error("Go-Quai Panicked")
			}
		}()
		var result *types.WorkObject
		select {
		case <-stop:
			// Outside abort, stop all miner threads
			close(abort)
		case result = <-locals:
			// One of the threads found a block, abort all others
			select {
			case results <- result:
			default:
				sha256pow.logger.WithFields(log.Fields{
					"mode":     "local",
					"sealhash": header.SealHash(),
				}).Warn("Sealing result is not read by miner")
			}
			close(abort)
		case <-sha256pow.update:
			// Thread count was changed on user request, restart
			close(abort)
			if err := sha256pow.Seal(header, results, stop); err != nil {
				sha256pow.logger.WithField("err", err).Error("Failed to restart sealing after update")
			}
		}
		// Wait for all miners to terminate and return the block
		pend.Wait()
	}()
	return nil
}

func (sha256pow *Sha256pow) ComputePowHash(header *types.WorkObjectHeader) (common.Hash, error) {
	// decode the bitcoin header
	headerBytes := header.AuxPow().Header()
	return types.ShaPowHash(headerBytes), nil
}

func (sha256pow *Sha256pow) Mine(header *types.WorkObject, abort <-chan struct{}, found chan *types.WorkObject) {
	sha256pow.MineToThreshold(header, params.WorkSharesThresholdDiff, abort, found)
}

func (sha256pow *Sha256pow) MineToThreshold(workObject *types.WorkObject, workShareThreshold int, abort <-chan struct{}, found chan *types.WorkObject) {
	if workShareThreshold <= 0 {
		log.Global.WithField("WorkshareThreshold", workShareThreshold).Error("WorkshareThreshold must be positive")
		return
	}

	target := new(big.Int).Div(common.Big2e256, workObject.WorkObjectHeader().ShaDiffAndCount().Difficulty())

	workObject = types.CopyWorkObject(workObject)
	bitcoinHeaderBytes := workObject.AuxPow().Header()
	bitcoinHeader, err := types.DecodeBitcoinHeader(bitcoinHeaderBytes)
	if err != nil {
		sha256pow.logger.WithField("err", err).Error("Error decoding bitcoin header")
		return
	}

	// Start generating random nonces until we abort or find a good one
	sha256pow.lock.Lock()
	seed := sha256pow.rand.Uint64()
	sha256pow.lock.Unlock()
	var (
		attempts  = int64(0)
		nonce     = seed
		powBuffer = new(big.Int)
	)
	sha256pow.logger.WithField("seed", seed).Trace("Started sha256pow search for new nonces")
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			sha256pow.logger.WithField("attempts", nonce-seed).Trace("Sha256pow nonce search aborted")
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				attempts = 0
			}
			// Compute the PoW value of this nonce using SHA256
			bitcoinHeader.Nonce = uint32(nonce)
			bitcoinHeaderBytes = bitcoinHeader.EncodeBinary()

			workObject.WorkObjectHeader().AuxPow().SetHeader(bitcoinHeaderBytes)

			powHash, err := sha256pow.ComputePowHash(workObject.WorkObjectHeader())
			if err != nil {
				sha256pow.logger.WithField("err", err).Error("Error computing SHA256 pow hash")
				break search
			}
			if powBuffer.SetBytes(powHash.Bytes()).Cmp(target) <= 0 {
				// Seal and return a block (if still needed)
				select {
				case found <- workObject:
					sha256pow.logger.WithFields(log.Fields{
						"attempts": nonce - seed,
						"nonce":    nonce,
					}).Trace("Sha256pow nonce found and reported")
				case <-abort:
					sha256pow.logger.WithFields(log.Fields{
						"attempts": nonce - seed,
						"nonce":    nonce,
					}).Trace("Sha256pow nonce found but discarded")
				}
				break search
			}
			nonce++
		}
	}
}
