package engine

import (
	"sync"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

type CarefulChunkLookup struct {
	resultLookup      map[DetectorKey][]string
	resultLookupMutex sync.Mutex

	detectorLookup      map[string][]DetectorKey
	detectorLookupMutex sync.Mutex

	skippableDetectors      map[DetectorKey]detectors.Detector
	skippableDetectorsMutex sync.Mutex
}

func (c *CarefulChunkLookup) GetResults(detectorKey DetectorKey) []string {
	c.resultLookupMutex.Lock()
	defer c.resultLookupMutex.Unlock()
	return c.resultLookup[detectorKey]
}

func (c *CarefulChunkLookup) AddResult(detectorKey DetectorKey, result string) {
	c.resultLookupMutex.Lock()
	defer c.resultLookupMutex.Unlock()
	_, exists := c.resultLookup[detectorKey]
	if exists {
		alreadyExists := false
		for _, existingDetector := range c.GetDetectors(result) {
			if existingDetector == detectorKey {
				alreadyExists = true
				break
			}
		}
		if !alreadyExists {
			c.resultLookup[detectorKey] = append(c.resultLookup[detectorKey], result)
		}
	} else {
		c.resultLookup[detectorKey] = []string{result}
	}
}

func (c *CarefulChunkLookup) GetDetectors(raw string) []DetectorKey {
	c.detectorLookupMutex.Lock()
	defer c.detectorLookupMutex.Unlock()
	return c.detectorLookup[raw]
}

func (c *CarefulChunkLookup) AddDetector(raw string, detectorKey DetectorKey) {
	c.detectorLookupMutex.Lock()
	defer c.detectorLookupMutex.Unlock()
	c.detectorLookup[raw] = append(c.detectorLookup[raw], detectorKey)
}

func (c *CarefulChunkLookup) GetSkippableDetectors() map[DetectorKey]detectors.Detector {
	return c.skippableDetectors
}

func (c *CarefulChunkLookup) AddSkippableDetector(detectorKey DetectorKey, detector detectors.Detector) {
	c.skippableDetectorsMutex.Lock()
	defer c.skippableDetectorsMutex.Unlock()
	c.skippableDetectors[detectorKey] = detector
}

func NewCarefulChunkLookup() *CarefulChunkLookup {
	return &CarefulChunkLookup{
		resultLookup:       make(map[DetectorKey][]string),
		detectorLookup:     make(map[string][]DetectorKey),
		skippableDetectors: make(map[DetectorKey]detectors.Detector),
	}
}
