# aegaeon test code
# loads from lib/aegaeon/[lindex $argv 0]/aegaeon.tcl

load lib/aegaeon/[lindex $argv 0]/aegaeon.so

mowgli_bootstrap

set el [eventloop_create]
set v [vio_create]

vio_fileevent_readable_set $v [list readStuff $v]
vio_fileevent_writable_set $v tellit
proc readwrap {vp outvar maxlen} {
	upvar 1 $outvar outvar
	set retval [vio_read $vp o o $maxlen]
	set outvar $o(o)
	return retval
}

proc tellit {} {
	puts stdout "available for writing $::v"
}

proc timeit {ignored} {
	puts stdout "tick, tock"
}

timer_add $el ticktock timeit ignored 1

proc readStuff {vp} {
	global loggedin
	set ov ""
	if {!$loggedin} {
		vio_send $v "PASS areallydumpassword\r\n"
		vio_send $v "NICK Mowglibot\r\n"
		vio_send $v "USER hi * 8 :A bot that does nothing\r\n"
		set loggedin 1
	}
	if {[set outbytes [readwrap $vp ov 512]] > 0} {
		puts stdout [format "Read %s bytes from %s: %s" $outbytes $vp $ov]
	} else {
		puts stdout [format "Got error %s from %s, exiting" $outbytes $vp]
		vio_eventloop_detach $vp
		exit
	}
}

set loggedin 0

puts stdout [vio_socket $v $AF_INET $SOCK_STREAM $IPPROTO_TCP]
puts stdout [vio_connect $v "127.0.0.1" "8500" 0 $AF_INET $SOCK_STREAM 0]

vio_eventloop_attach $v $el

eventloop_fire $el
