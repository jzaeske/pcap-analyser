package main

import (
	"./analyser"
	logger "./log"
	"encoding/xml"
	"flag"
	"io/ioutil"
	"log"
)

var configFile string

var split string

func init() {
	flag.StringVar(&configFile, "config", "", "xml config file")
}

func main() {
	flag.Parse()

	if configFile != "" {
		if data, err := ioutil.ReadFile(configFile); err == nil {

			var config analyser.AnalysisConfig

			if err := xml.Unmarshal(data, &config); err != nil {
				log.Fatal(err)
			}

			logger.SetLogFile(config.Settings.LogFile)

			if split != "" {
				//s := splitter.NewSplitter(split)
				//s.Run(pcapList)
			} else {
				analyzer := analyser.NewAnalyzer(&config)
				analyzer.Run()
				analyzer.ExportCsv()
			}
		} else {
			log.Fatal(err)
		}
	}
}
