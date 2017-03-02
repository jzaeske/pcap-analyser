package components

import (
	"bufio"
	"github.com/google/gopacket/pcapgo"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// TODO: Hier nicht so sinnvoll...
var minDate = time.Date(2017, 12, 31, 0, 0, 0, 0, time.UTC)
var maxDate = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

var wg sync.WaitGroup = sync.WaitGroup{}

// File Workers organize synchronization via a sync.WaitGroup. Use Wait() to wait for all running File Workers to finish
func WaitForFileWorkers() {
	log.Println("Wait for all file workers to finish")
	wg.Wait()
	log.Println("All FileWorkers finished")
}

type FileWorker struct {
	name     string
	chain	 *Parser
	r        *bufio.Reader
}

func NewFileWorker(name string, chain *Parser) (w FileWorker) {
	w.name = name
	w.chain = chain
	return
}

func (w FileWorker) Run(files chan string, chainSync *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	for file := range files {
		w.handleFile(file)
	}
	close(w.chain.Input)
	chainSync.Wait()
	log.Printf("FileWorker %s finished\n", w.name)
}

func (w *FileWorker) handleFile(file string) {
	f, err := os.Open(file)
	if err != nil {
		log.Panic(err)
		return
	}
	defer f.Close()

	// add a large buffer between File Reader and gcapgo to reduce the amount of IO reads to the filesystem
	w.r = bufio.NewReaderSize(f, bufferSize)

	if r, err := pcapgo.NewReader(w.r); err != nil {
		log.Panic(err)
	} else {
		log.Printf("FileWorker %s handles file %s\n", w.name, file)
		filename := normalizeFilename(file)

		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				if err == io.EOF {
					// ok: that's usual
					break
				} else if err == io.ErrUnexpectedEOF {
					// if capture terminates unexpected it may happen that pcap file is not generated
					// consistent. The last record header claims to have N bytes captured, but the
					// file has only M < N bytes left. In this case the buffer will not get filled
					// completely and pcapgo return an ErrUnexptectedEOF.
					// Those packages should not be considered in an analysis.
					log.Printf("File %s: has unexcepted EOF. Claimed package with %d bytes " +
						"can not be filled completely and will be ignored in analysis.\n" +
						"Package Data%v\n", filename, len(data), data)
					break
				} else {
					break
				}

			}
			w.chain.Input <- UnparsedMeasurement{&data, &ci}

		}
	}
}

func normalizeFilename(filename string) string {
	return filename[strings.LastIndex(filename, "/")+1:]
}
