package config

import "../components"

type ChainStart struct {
	File      string `xml:"file,omitempty`
	Directory string `xml:"directory,omitempty"`
	Output    int    `xml:"next,attr`
}

type ChainDefinition struct {
	Element int `xml:"chain,attr`
	Output  int `xml:"next,attr`
}

// Example:
// <Parser id="1"></Parser>
// <Filter id="2"></Filter>
// <Counter id="3"></Counter>
// <Endpoint id="4"></Endpoint>
// <Endpoint id="5"></Endpoint>
//
// <ChainDefinition>
// 	<File>./test.pcap</File>
//	<Directory>/home/jan/test/</Directory>
//	<Output format="csv">/home/jan/out/report.csv</Output>
//	<Startb id="1" />
//	<Chain from="1" to="2" />
//	<Chain from="2" to="3" trash="5" />
//	<Chain from="3" to="4" />
// </ChainDefinition>
// <ChainStart next="1">
// 	<Directory>/home/jan/test/</Directory>
// </ChainStart>
// <ChainDef

type Reader struct {
	configFile string
}

func NewReader(file string) (r *Reader) {
	return &Reader{configFile: file}
}

func (r *Reader) readChainFromConfig() (ch *components.Chain) {

}
