package analyser

import (
	"encoding/xml"
	com "./components"
	"./chains"
	"sync"
	"log"
	"os"
	"io/ioutil"
	"sort"
	"strings"
	"errors"
)

type AnalysisConfig struct {
	ConfigFile     string
	Components     Components
	Chain          []Connect
	Settings       Settings
	SpecialPackets SpecialPackets
}

type Connect struct {
	Input  string `xml:"input,attr"`
	Output string `xml:"output,attr"`
	No     string `xml:"no,attr"`
	Other  string `xml:"other,attr"`
}

type Components struct {
	ChainComponents []com.Component
}

type SpecialPackets struct {
	Skip []Skip
}

type Skip struct {
	File         string `xml:"file,attr"`
	PacketNumber int `xml:"packetNumber,attr"`
}

func (sp *SpecialPackets) IsSkip(file string, number int) bool {
	for _, skip := range sp.Skip {
		if skip.File == file && skip.PacketNumber == number {
			return true
		}
	}
	return false
}

type Settings struct {
	Input      string
	Output     string
	LogFile    string
	Concurrent int
}

func (a *AnalysisConfig) GetChain() (chain *com.Parser, wg *sync.WaitGroup) {
	packets := make(chan chains.UnparsedMeasurement, 2000)
	wg = &sync.WaitGroup{}
	endpoint := com.Endpoint{Group: wg}

	componentsMap := buildComponentsMap(a.Components)
	for _, connect := range a.Chain {
		id := connect.Input
		if component, ok := componentsMap[id]; ok {
			if connect.Output == "FILE" {
				if parser, ok := component.(*com.Parser); ok {
					parser.Input = packets
					chain = parser
				} else {
					log.Fatalln("only parser can be connected to FILE")
				}
			} else if connect.Output != "" {
				if output, ok := componentsMap[connect.Output]; ok {
					if sc := com.ConvertStreamChain(output); sc != nil {
						if si := com.ConvertStreamInput(component); si != nil {
							si.Input(sc.Output())
						} else {
							log.Fatalf("incompatible chain: %s -> %s", output, id)
						}
					} else if pc := com.ConvertPacketChain(output); pc != nil {
						if pi := com.ConvertPacketInput(component); pi != nil {
							pi.Input(pc.Output())
						} else {
							log.Fatalf("incompatible chain: %s -> %s", output, id)
						}
					}
				}
			} else if connect.No != "" {
				if no, ok := componentsMap[connect.No]; ok {
					if f := com.ConvertFilter(no); &f != nil {
						if pi := com.ConvertPacketInput(component); pi != nil {
							pi.Input(f.No())
						} else {
							log.Fatalf("incompatible chain: %s -> %s", no, id)
						}
					} else {
						log.Fatalf("%s is not a filter", no)
					}
				}
			} else if connect.Other != "" {
				if other, ok := componentsMap[connect.Other]; ok {
					if sc := com.ConvertStreamChain(other); sc != nil {
						otherChannel := sc.Other()
						switch tt := otherChannel.(type) {
						case *chan chains.TCPStream:
							if si := com.ConvertStreamInput(component); si != nil {
								si.Input(otherChannel.(*chan chains.TCPStream))
							} else {
								log.Fatalf("incompatible chain: %s -> %s", other, id)
							}
						case *chan chains.Measurement:
							if pi := com.ConvertPacketInput(component); pi != nil {
								pi.Input(otherChannel.(*chan chains.Measurement))
							} else {
								log.Fatalf("incompatible chain: %s -> %s", other, id)
							}
						default:
							log.Fatalf("Type %s not compatible", tt)
						}
					} else {
						log.Fatalf("%s is not a steamChain", other)
					}
				}
			}
		} else {
			log.Fatalf("no component with id '%s' specified", id)
		}
	}

	for _, component := range componentsMap {
		endpoint.AddComponent(component)
		go component.Run()
	}

	endpoint.Run()

	return
}

func (a *AnalysisConfig) GetInputFiles() (pcapList []string, e error) {
	if a.Settings.Input != "" {
		path := a.Settings.Input
		if stat, err := os.Stat(path); err == nil {
			if stat.IsDir() {
				pcapList = collectFilesOfType(path, ".pcap,.pcap.gz")
			} else {
				pcapList = []string{path}
				a.Settings.Concurrent = 1
			}
			return
		}
	}
	e = errors.New("No input specified")
	return
}

func collectFilesOfType(path string, suffixes string) []string {
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

func buildComponentsMap(c Components) (componentsMap map[string]com.Component) {
	componentsMap = make(map[string]com.Component)
	for _, comOrig := range c.ChainComponents {
		id := comOrig.ComId()
		comp := comOrig.Copy()
		comp.Init()
		componentsMap[id] = comp
	}
	return
}

func (a *AnalysisConfig) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// decode inner elements
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch tt := t.(type) {
		case xml.StartElement:
			switch tt.Name.Local {
			case "Settings":
				{
					settings := new(Settings)
					err = d.DecodeElement(settings, &tt)
					if err != nil {
						return err
					}
					a.Settings = *settings
				}
			case "SpecialPackets":
				{
					special := new(SpecialPackets)
					err = d.DecodeElement(special, &tt)
					if err != nil {
						return err
					}
					a.SpecialPackets = *special
				}
			case "Connect":
				{
					connect := new(Connect)
					err = d.DecodeElement(connect, &tt)
					if err != nil {
						return err
					}
					a.Chain = append(a.Chain, *connect)
				}
			case "Components":
				{
					components := new(Components)
					err = d.DecodeElement(components, &tt)
					if err != nil {
						return err
					}
					a.Components = *components
				}
			}
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}

	}
	return nil
}

func (c *Components) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// decode inner elements
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch tt := t.(type) {
		case xml.StartElement:
			var comp com.Component
			switch tt.Name.Local {
			case "Parser":
				comp = new(com.Parser)
			case "Composer":
				comp = new(com.Composer)
			case "StreamCounter":
				comp = new(com.StreamCounter)
			case "PacketCounter":
				comp = new(com.PacketCounter)
			case "BackscatterFilter":
				comp = new(com.BackscatterFilter)
			case "Stat":
				comp = new(com.Stat)
			case "Filter":
				comp = new(com.Filter)
			default:
				log.Fatalln("Type not found", tt.Name.Local)
			}
			err = d.DecodeElement(comp, &tt)
			if err != nil {
				return err
			}
			c.ChainComponents = append(c.ChainComponents, comp)
		case xml.EndElement:
			if tt == start.End() {
				return nil
			}
		}

	}
	return nil
}
