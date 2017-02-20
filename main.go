package main

import (
	"./analyser"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
)

var inputFile string

var inputPath string

var reportFile string

var concurrentFiles int

var summary bool

func init() {
	flag.StringVar(&inputFile, "inFile", "", "File to analyse")
	flag.StringVar(&inputPath, "inDir", "", "Directory to scan for PCAP Files")
	flag.StringVar(&reportFile, "outFile", "", "File to write report. If not set, stdout is used")
	flag.IntVar(&concurrentFiles, "concurrent", 1, "Number of PCAP Files parsed concurrently")
	flag.BoolVar(&summary, "summary", false, "Only generate per File Summary")
}

func main() {
	var pcapList []string

	flag.Parse()

	// Check Input File
	if inputFile != "" {
		if _, err := os.Stat(inputFile); err != nil {
			log.Fatalf("Error occured: %s\n", err)
			return
		}
		pcapList = []string{inputFile}
	} else if inputPath != "" {
		fmt.Println(inputPath)
		stat, err := os.Stat(inputPath)
		if err != nil {
			log.Fatalf("Error occured: %s\n", err)
			return
		}
		if !stat.IsDir() {
			log.Fatalln("inDir is not a directory")
			return
		}
		pcapList = collectFilesOfType(inputPath, ".pcap,.pcap.gz", true)
	} else {
		log.Fatalln("Neither inFile nor inDir specified")
		return
	}

	analyzer := analyser.NewAnalyzer(pcapList, concurrentFiles)
	analyzer.Run(summary)
	analyzer.ExportCsv(reportFile)

}

type ByFileSize []os.FileInfo

func (s ByFileSize) Len() int {
	return len(s)
}
func (s ByFileSize) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ByFileSize) Less(i, j int) bool {
	return s[i].Size() > s[j].Size()
}

func collectFilesOfType(path string, suffixes string, sorted bool) []string {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	fileList := make([]string, 0)

	sort.Sort(ByFileSize(files))

	for _, file := range files {
		name := file.Name()
		for _, suffix := range strings.Split(suffixes, ",") {
			if strings.HasSuffix(name, suffix) {
				fileList = append(fileList, path+"/"+name)
			}
		}
	}

	return fileList
}
