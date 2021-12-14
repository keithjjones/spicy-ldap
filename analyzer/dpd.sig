signature dpd_ldap_client_udp {
  ip-proto == udp
  payload /^\x30\x32/
}

signature dpd_ldap_server_udp {
  ip-proto == udp
  payload /^\x30\x84/
  requires-reverse-signature dpd_ldap_client_udp
  enable "spicy_LDAP_UDP"
}

signature dpd_ldap_client_tcp {
  ip-proto == tcp
  payload /^\x30\x32/
}

signature dpd_ldap_server_tcp {
  ip-proto == tcp
  payload /^\x30\x84/
  requires-reverse-signature dpd_ldap_client_tcp
  enable "spicy_LDAP_TCP"
}