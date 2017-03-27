package main

import (
	"./analyser"
	_ "./log"
	"./splitter"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

var inputFile string

var inputPath string

var reportFile string

var concurrentFiles int

var split string

func init() {
	flag.StringVar(&inputFile, "inFile", "", "File to analyse")
	flag.StringVar(&inputPath, "inDir", "", "Directory to scan for PCAP Files")
	flag.StringVar(&reportFile, "outFile", "", "File to write report. If not set, stdout is used")
	flag.IntVar(&concurrentFiles, "concurrent", 1, "Number of PCAP Files parsed concurrently")
	flag.StringVar(&split, "split", "", "Split the input files on the defined criteria")
}

func main() {
	start := time.Now()
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

	if split != "" {
		s := splitter.NewSplitter(split)
		s.Run(pcapList)
	} else {
		analyzer := analyser.NewAnalyzer(pcapList, concurrentFiles)
		analyzer.Run()
		analyzer.ExportCsv(reportFile)
	}

	elapsed := time.Since(start)
	fmt.Printf("Took: %s\n", elapsed)
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

type ByFileName []os.FileInfo

func (s ByFileName) Len() int {
	return len(s)
}
func (s ByFileName) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s ByFileName) Less(i, j int) bool {
	return s[i].Name() < s[j].Name()
}

func collectFilesOfType(path string, suffixes string, sorted bool) []string {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	fileList := make([]string, 0)

	if split != "" {
		sort.Sort(ByFileName(files))
	} else {
		sort.Sort(ByFileSize(files))
	}

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
