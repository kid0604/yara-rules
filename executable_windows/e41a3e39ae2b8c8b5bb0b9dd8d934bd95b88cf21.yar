rule _case_5295_sig_7jkio8943wk
{
	meta:
		description = "5295 - file 7jkio8943wk.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-12"
		hash1 = "dee4bb7d46bbbec6c01dc41349cb8826b27be9a0dcf39816ca8bd6e0a39c2019"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = " (os error other os erroroperation interruptedwrite zerotimed outinvalid datainvalid input parameteroperation would blockentity " ascii
		$s2 = "already existsbroken pipeaddress not availableaddress in usenot connectedconnection abortedconnection resetconnection refusedper" ascii
		$s3 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
		$s4 = "UnexpectedEofNotFoundPermissionDeniedConnectionRefusedConnectionResetConnectionAbortedNotConnectedAddrInUseAddrNotAvailableBroke" ascii
		$s5 = "nPipeAlreadyExistsWouldBlockInvalidInputInvalidDataTimedOutWriteZeroInterruptedOtherN" fullword ascii
		$s6 = "failed to fill whole buffercould not resolve to any addresses" fullword ascii
		$s7 = " (os error other os erroroperation interruptedwrite zerotimed outinvalid datainvalid input parameteroperation would blockentity " ascii
		$s8 = "mission deniedentity not foundunexpected end of fileGetSystemTimePreciseAsFileTime" fullword ascii
		$s9 = "invalid socket addressinvalid port valuestrings passed to WinAPI cannot contain NULsinvalid utf-8: corrupt contentsinvalid utf-8" ascii
		$s10 = "invalid socket addressinvalid port valuestrings passed to WinAPI cannot contain NULsinvalid utf-8: corrupt contentsinvalid utf-8" ascii
		$s11 = "\\data provided contains a nul byteSleepConditionVariableSRWkernel32ReleaseSRWLockExclusiveAcquireSRWLockExclusive" fullword ascii
		$s12 = "fatal runtime error: " fullword ascii
		$s13 = "assertion failed: key != 0WakeConditionVariable" fullword ascii
		$s14 = "kindmessage" fullword ascii
		$s15 = "0x000102030405060708091011121314151617181920212223242526272829303132333435363738394041424344454647484950515253545556575859606162" ascii
		$s16 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writing non-UTF-8 byte sequences" fullword ascii
		$s17 = "OS Error  (FormatMessageW() returned invalid UTF-16) (FormatMessageW() returned error )formatter error" fullword ascii
		$s18 = "FromUtf8Errorbytes" fullword ascii
		$s19 = "  VirtualProtect failed with code 0x%x" fullword ascii
		$s20 = "invalid utf-8 sequence of  bytes from index incomplete utf-8 byte sequence from index " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and 8 of them
}
