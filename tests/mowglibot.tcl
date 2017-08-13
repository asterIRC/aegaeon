# aegaeon test code
# loads from lib/aegaeon/[lindex $argv 0]/aegaeon.tcl

load lib/aegaeon/[lindex $argv 0]/aegaeon.so

mowgli_bootstrap

set el [eventloop_create]
set v [vio_create]

vio_fileevent_readable_set $v [list readStuff $v]
vio_fileevent_writable_set $v [list logIn $v]
proc readwrap {vp outv maxlen} {
	upvar 1 $outv outvar
	set retval [vio_recv $vp $maxlen o o]
	set outvar $o(o)
	return $retval
}

proc tellit {} {
	puts stdout "available for writing $::v"
}

proc timeit {ignored} {
	puts stdout "tick, tock"
}

timer_add $el ticktock timeit ignored 1

proc logIn {vp} {
	global loggedin
	if {$loggedin == 0} {
		vio_send $vp "PASS areallydumbpassword\r\n"
		vio_send $vp "NICK Mowglibot\r\n"
		vio_send $vp "USER hi * 8 :A bot that does nothing\r\n"
		set loggedin 1
	}
}

proc readStuff {vp} {
	global loggedin
	set ov ""
	if {[set outbytes [readwrap $vp ov 512]] > 0} {
		puts stdout [format "Read %s bytes from %s: %s" $outbytes $vp $ov]
	} else {
		puts stdout [format "Got error %s from %s, exiting" [vio_strerror $vp] $vp]
		vio_eventloop_detach $vp
		exit
	}
}

set loggedin 0

puts stdout [vio_socket $v $AF_INET $SOCK_STREAM $IPPROTO_SCTP]
puts stdout [set theError [vio_connect $v "127.0.0.1" "6667" 0 $AF_INET $SOCK_STREAM 0]]

if {($theError >> 8) == 0} {vio_eventloop_attach $v $el} {puts stdout {Unable to connect!}; exit}

eventloop_fire $el
