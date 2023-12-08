import "math"
import "pe"

rule PellesC_alt_1 : Pelle Orinius
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "www.smorgasbordet.com/pellesc"
		os = "windows"
		filetype = "executable"

	strings:
		$aa0 = " -- terminating\x0D\x0A\x00 -- terminating\x0A\x00CRT: \x00unexpected error\x00" wide ascii nocase
		$aa1 = "unhandled exception (main)\x00unhandled exception in thread\x00unable to create thread\x00unable to destroy semaphore\x00" wide ascii nocase
		$aa2 = "unable to wait on semaphore\x00unable to post semaphore\x00unable to init semaphore\x00unable to unlock mutex\x00unable to lock mutex\x00unable to init mutex\x00" wide ascii nocase
		$aa3 = "invalid stream lock number\x00corrupt per-thread data\x00out of memory\x00unable to init threads\x00unable to init HEAP" wide ascii nocase

	condition:
		3 of ($aa*) and (pe.linker_version.major==2) and (pe.linker_version.minor==50)
}
