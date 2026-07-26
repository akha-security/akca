package app

import (
	"encoding/json"
	"errors"

	"github.com/akha-security/akca/engine/internal/distributed"
)

func (e *Engine) EnqueueDistributedJob(spec distributed.Spec) (string, error) {
	if e.jobs == nil {
		return "", errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Enqueue(spec)
}

func (e *Engine) LeaseDistributedJob(workerID string) (distributed.Job, error) {
	if e.jobs == nil {
		return distributed.Job{}, errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Lease(workerID)
}

func (e *Engine) GetDistributedJob(jobID string) (distributed.Job, error) {
	if e.jobs == nil {
		return distributed.Job{}, errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Get(jobID)
}

func (e *Engine) HeartbeatDistributedJob(jobID, workerID string) error {
	if e.jobs == nil {
		return errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Heartbeat(jobID, workerID)
}

func (e *Engine) CheckpointDistributedJob(jobID, workerID string, checkpoint json.RawMessage) error {
	if e.jobs == nil {
		return errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Checkpoint(jobID, workerID, checkpoint)
}

func (e *Engine) CompleteDistributedJob(jobID, workerID string) error {
	if e.jobs == nil {
		return errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Complete(jobID, workerID)
}

func (e *Engine) FailDistributedJob(jobID, workerID, message string) error {
	if e.jobs == nil {
		return errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Fail(jobID, workerID, errors.New(message))
}

func (e *Engine) CancelDistributedJob(jobID string) error {
	if e.jobs == nil {
		return errors.New("distributed coordinator is unavailable")
	}
	return e.jobs.Cancel(jobID)
}
