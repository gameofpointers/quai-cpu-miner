package scrypt

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

type Scryptpow struct {
	threads int              // Number of threads to mine with (0 = number of cores)
	rand    *rand.Rand       // Random number source to use for mining
	shared  consensus.Engine // Shared miner to use (if any)

	lock   sync.Mutex    // Protects the PoW fields during operation
	update chan struct{} // Notifies a change in the mining threads
	logger *log.Logger   // Logger used by the PoW engine
}

func NewScryptpow(threads int, logger *log.Logger) *Scryptpow {
	return &Scryptpow{
		threads: threads,
		update:  make(chan struct{}),
		logger:  logger,
	}
}

// Seal implements consensus.Engine, attempting to find a nonce that satisfies
// the header's difficulty requirements.
func (scryptpow *Scryptpow) Seal(header *types.WorkObject, results chan<- *types.WorkObject, stop <-chan struct{}) error {
	// If we're running a shared PoW, delegate sealing to it
	if scryptpow.shared != nil {
		return scryptpow.shared.Seal(header, results, stop)
	}
	// Create a runner and the multiple search threads it directs
	abort := make(chan struct{})

	scryptpow.lock.Lock()
	threads := scryptpow.threads
	if scryptpow.rand == nil {
		seed, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			scryptpow.lock.Unlock()
			return err
		}
		scryptpow.rand = rand.New(rand.NewSource(seed.Int64()))
	}
	scryptpow.lock.Unlock()
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
					scryptpow.logger.WithFields(log.Fields{
						"error":      r,
						"stacktrace": string(debug.Stack()),
					}).Error("Go-Quai Panicked")
				}
			}()
			defer pend.Done()
			scryptpow.Mine(header, abort, locals)
		}()
	}
	// Wait until sealing is terminated or a nonce is found
	go func() {
		defer func() {
			if r := recover(); r != nil {
				scryptpow.logger.WithFields(log.Fields{
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
				scryptpow.logger.WithFields(log.Fields{
					"mode":     "local",
					"sealhash": header.SealHash(),
				}).Warn("Sealing result is not read by miner")
			}
			close(abort)
		case <-scryptpow.update:
			// Thread count was changed on user request, restart
			close(abort)
			if err := scryptpow.Seal(header, results, stop); err != nil {
				scryptpow.logger.WithField("err", err).Error("Failed to restart sealing after update")
			}
		}
		// Wait for all miners to terminate and return the block
		pend.Wait()
	}()
	return nil
}

func (scryptpow *Scryptpow) ComputePowHash(header *types.WorkObjectHeader) (common.Hash, error) {
	// decode the bitcoin header
	return header.AuxPow().Header().PowHash(), nil
}

func (scryptpow *Scryptpow) Mine(header *types.WorkObject, abort <-chan struct{}, found chan *types.WorkObject) {
	scryptpow.MineToThreshold(header, params.WorkSharesThresholdDiff, abort, found)
}

func (scryptpow *Scryptpow) MineToThreshold(workObject *types.WorkObject, workShareThreshold int, abort <-chan struct{}, found chan *types.WorkObject) {
	if workShareThreshold <= 0 {
		log.Global.WithField("WorkshareThreshold", workShareThreshold).Error("WorkshareThreshold must be positive")
		return
	}

	target := new(big.Int).Div(common.Big2e256, workObject.WorkObjectHeader().ScryptDiffAndCount().Difficulty())

	workObject = types.CopyWorkObject(workObject)
	bitcoinHeader := workObject.AuxPow().Header()

	// Start generating random nonces until we abort or find a good one
	scryptpow.lock.Lock()
	seed := scryptpow.rand.Uint64()
	scryptpow.lock.Unlock()
	var (
		attempts  = int64(0)
		nonce     = seed
		powBuffer = new(big.Int)
	)
	scryptpow.logger.WithField("seed", seed).Trace("Started scryptpow search for new nonces")
search:
	for {
		select {
		case <-abort:
			// Mining terminated, update stats and abort
			scryptpow.logger.WithField("attempts", nonce-seed).Trace("Scryptpow nonce search aborted")
			break search

		default:
			// We don't have to update hash rate on every nonce, so update after after 2^X nonces
			attempts++
			if (attempts % (1 << 15)) == 0 {
				attempts = 0
			}
			// Compute the PoW value of this nonce using SHA256
			bitcoinHeader.SetNonce(uint32(nonce))

			workObject.WorkObjectHeader().AuxPow().SetHeader(bitcoinHeader)

			powHash, err := scryptpow.ComputePowHash(workObject.WorkObjectHeader())
			if err != nil {
				scryptpow.logger.WithField("err", err).Error("Error computing Scrypt pow hash")
				break search
			}
			if powBuffer.SetBytes(powHash.Bytes()).Cmp(target) <= 0 {
				// Seal and return a block (if still needed)
				select {
				case found <- workObject:
					scryptpow.logger.WithFields(log.Fields{
						"attempts": nonce - seed,
						"nonce":    nonce,
					}).Trace("Scryptpow nonce found and reported")
				case <-abort:
					scryptpow.logger.WithFields(log.Fields{
						"attempts": nonce - seed,
						"nonce":    nonce,
					}).Trace("Scryptpow nonce found but discarded")
				}
				break search
			}
			nonce++
		}
	}
}
