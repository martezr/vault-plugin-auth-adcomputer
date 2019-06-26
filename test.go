package main

import (
//	"crypto/tls"
	"fmt"
	"log"

	"gopkg.in/ldap.v2"
)

func main()  {
  // Bind username and password
  bindusername := "administrator@grt.local"
  bindpassword := "VAe(f-k(iQJ"
  ldapserver := "34.232.50.91"
  ldapport := 389

  l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapserver, ldapport))
  if err != nil {
      log.Fatal(err)
  }
  defer l.Close()

  // First bind with a read only user
  err = l.Bind(bindusername, bindpassword)
  if err != nil {
      log.Fatal(err)
  }

  guid, name := GetMachineInfo(l, "dc=grt,dc=local","GRTDC01", "26 FF FA C5 F8 D0 5F 42 8D 3E 86 C6 29 F3 28 AE")
  fmt.Printf("Computer account attributes: %s", guid)
  fmt.Printf("Computer Name: %s \n", name)

}

// Reference: Scott Sutherland (@_nullbind)
func GetMachineInfo(conn *ldap.Conn, baseDN string, computername string, guid string)(outguid, name string ) {

	attributes := []string{
		"name",
		"objectGUID"}

  // TODO: Add computername to filter to find just the desired match
	filter := "(&(sAMAccountType=805306369))"
	sr := ldapSearch(baseDN, filter, attributes, conn)

  // FIRST: Check if the computer name provided exists within Active Directory
  if len(sr.Entries) != 1 {
      log.Fatal("Requested computer account does not exist")
  }

  // Fetch computer account GUID
  ldapGuid := sr.Entries[0].GetAttributeValue("objectGUID")
  fmt.Printf("GUID: %x \n", ldapGuid)

  accountName := sr.Entries[0].GetAttributeValue("name")
  fmt.Printf("Computer Name: %s \n", accountName)

  if guid != ldapGuid {
    fmt.Printf("Passed GUID: %x \n", guid)
    log.Fatal("Invalid GUID passed")
  }

  return ldapGuid, accountName
}

func ldapSearch(searchDN string, filter string, attributes []string, conn *ldap.Conn) *ldap.SearchResult {

	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := conn.SearchWithPaging(searchRequest, 200)
	if err != nil {
		log.Println(err)
	}

	return sr

}
