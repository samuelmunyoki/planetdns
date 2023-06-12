package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	// International Root servers
	ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53,192.36.148.17,192.58.128.30,193.0.14.129,199.7.83.42,202.12.27.33"

	// Kenya's Dedicated root servers
	ROOT_SERVERS_KE = "199.7.91.13,192.203.230.10,192.5.5.241,192.203.230.10,199.7.83.42,192.58.128.30"
)
func main (){
	fmt.Println("PlanetDNS server starting... 🔥")

	// Listening to local port 53 for DNS requests
	packetConnection, err := net.ListenPacket("udp", ":53")
	if err != nil {
		fmt.Printf("error starting PlanetDNS server %v", err)
	}

	fmt.Print("Successfully started. ✔️\n")
	// Closing the Connection later
	defer packetConnection.Close()

	// Capturing packets form the port
	for {

		// Making a buffer
		buf :=make([]byte, 512)


		n, addr, err := packetConnection.ReadFrom(buf)
		if err != nil {
			fmt.Printf("error reading packet %v from %v", err, addr)
			continue
		}
		fmt.Printf("Read %v bytes \n", n)


		// Handling the DNS request
		go handlePacket(packetConnection, addr, buf)

	}
}
func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error{
	fmt.Println("Handling DNS packet.")

	// Creating a Parser for the DNS request
	p := dnsmessage.Parser{}

	// Starting the parser
	header, err := p.Start(buf)
	if err != nil{
		fmt.Printf("error %v: \n", err) 
	}

	// Extracting the DNS question
	question, err := p.Question()
	if err != nil{
		fmt.Printf("Error parsing DNS Question")
	}
	
	// Handling the DNS requesting by sending to root servers
	response, err := handleQuery(getRootServers(), question)
	if err != nil {
		return err
	}

	// Getting DNS ID
	response.Header.ID = header.ID

	// Packing the DNS response
	responseBuffer, err := response.Pack()
	if err != nil {
		return err
	}

	// Writing the DNS response buffer back to DNS client
	_, err = pc.WriteTo(responseBuffer, addr)
	if err != nil {
		return err
	}

	return nil

}

func getRootServers() []net.IP {

	// Initializing empty IP address array
	rootServers := []net.IP{}

	// Parsing the Root servers' IP to a readable format
	for _, rootServer := range strings.Split(ROOT_SERVERS_KE, ",") {
		rootServers = append(rootServers, net.ParseIP(rootServer))
	}
	return rootServers
}

func outgoingDnsQuery (servers []net.IP, question dnsmessage.Question)(*dnsmessage.Parser, *dnsmessage.Header, error){
	uid, err := randomUint16()

	if err != nil{
		return nil, nil, err
	}
	// Building the DNS question
	dnsq := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: *uid,
			Response: false,
			OpCode: dnsmessage.OpCode(0),
		},
		Questions: []dnsmessage.Question{question},
	}

	// Packing the DNS query to a buffer
 	buff, err := dnsq.Pack()
	if err != nil {
		return nil, nil, err
	}

	// Establishing a UDP connection to the root servers
	var rootConn net.Conn
	for _, server := range servers {
		rootConn, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			break
		}
	}

	// Handling error incase root servers are not connected
	if rootConn == nil {
		return nil, nil, fmt.Errorf("failed to connect to root servers: %s", err)
	}

	// Sendind DNS query to root servers
	_, err = rootConn.Write(buff)
	if err != nil {
		return nil, nil, err
	}


	// Getting the response
	answer := make([]byte, 512)
	n, err := bufio.NewReader(rootConn).Read(answer)
	// Handling the response from root servers error
	if err != nil {
		return nil, nil, err
	}

	// Closing any open root server udp connection
	rootConn.Close()

	var p dnsmessage.Parser

	// Parsing the response and reading the bytes read from o:n
	header, err := p.Start(answer[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("parser start error: %s", err)
	}

	// Checking if error in the Questions
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, err
	}

	// Comparing the DNS query questions and those recieved
	if len(questions) != len(dnsq.Questions) {
		return nil, nil, fmt.Errorf("answer packet doesn't match dns query questions")
	}

	// Skipping DNS response questions
	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}


	// Returning parser [has answers] and header
	return &p, &header, nil

}



func handleQuery(servers []net.IP, question dnsmessage.Question)(*dnsmessage.Message, error )  {
		fmt.Printf("Question: %+v\n", question)

	for i := 0; i < 3; i++ {
		dnsAnswer, header, err := outgoingDnsQuery(servers, question)
		
		// return error got
		if err != nil {
			return nil, err
		}

		// Parsing answers
		pAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}

		// Return Authoritative servers for the DNS query
		if header.Authoritative {
			return &dnsmessage.Message{
				Header:  dnsmessage.Header{Response: true},
				Answers: pAnswers,
			}, nil
		}

		// Parsing DNS authorities
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}

		// If no DNS authorities found
		if len(authorities) == 0 {
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
					RCode: dnsmessage.RCodeNameError,
				},
			}, nil
		}

		// building nameservers string
		nameservers := make([]string, len(authorities))
		for k, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				nameservers[k] = authority.Body.(*dnsmessage.NSResource).NS.String()
			}
		}

		// Extracting any additionals
		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}

		fmt.Printf("Additionals: %v: \n\n", additionals)

		// Setting the false to later determine if NS were got
		newResolverServersFound := false
		servers = []net.IP{}

		for _, additional := range additionals {

			// Checking for A records
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameserver := range nameservers {

					// Checking if a NS was found
					if additional.Header.Name.String() == nameserver {
						newResolverServersFound = true
						servers = append(servers, additional.Body.(*dnsmessage.AResource).A[:])
					}
				}
			}
		}


		// If no namesever was found execute
		if !newResolverServersFound {

			for _, nameserver := range nameservers {
				if !newResolverServersFound {

					// Do another look up
					response, err := handleQuery(getRootServers(), dnsmessage.Question{Name: dnsmessage.MustNewName(nameserver), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
					if err != nil {
						fmt.Printf("warning: lookup of nameserver %s failed: %err\n", nameserver, err)
					} else {
						newResolverServersFound = true
						for _, answer := range response.Answers {
							if answer.Header.Type == dnsmessage.TypeA {
								servers = append(servers, answer.Body.(*dnsmessage.AResource).A[:])
							}
						}
					}
				}
			}
		}

		// fmt.Printf("Nameservers: %v: \n\n", servers)
		
	}
		
	return &dnsmessage.Message{
			Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
		}, nil

}

func randomUint16()(*uint16, error){
	var rn uint16
	rb := make([]byte, 2)

	_, err := rand.Read(rb)
	if err != nil {
		// fmt.Println("Failed to generate random number:", err)
		// panic("Error generating ID")
		return nil, err
	}

	rn = uint16(rb[0])<<8 | uint16(rb[1])
	return &rn, nil
}

