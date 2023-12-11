import "pe"

rule BlackShades_3 : Trojan RAT
{
	meta:
		description = "BlackShades RAT"
		author = "botherder https://github.com/botherder"
		os = "windows"
		filetype = "executable"

	strings:
		$mod1 = /(m)odAPI/
		$mod2 = /(m)odAudio/
		$mod3 = /(m)odBtKiller/
		$mod4 = /(m)odCrypt/
		$mod5 = /(m)odFuctions/
		$mod6 = /(m)odHijack/
		$mod7 = /(m)odICallBack/
		$mod8 = /(m)odIInet/
		$mod9 = /(m)odInfect/
		$mod10 = /(m)odInjPE/
		$mod11 = /(m)odLaunchWeb/
		$mod12 = /(m)odOS/
		$mod13 = /(m)odPWs/
		$mod14 = /(m)odRegistry/
		$mod15 = /(m)odScreencap/
		$mod16 = /(m)odSniff/
		$mod17 = /(m)odSocketMaster/
		$mod18 = /(m)odSpread/
		$mod19 = /(m)odSqueezer/
		$mod20 = /(m)odSS/
		$mod21 = /(m)odTorrentSeed/
		$tmr1 = /(t)mrAlarms/
		$tmr2 = /(t)mrAlive/
		$tmr3 = /(t)mrAnslut/
		$tmr4 = /(t)mrAudio/
		$tmr5 = /(t)mrBlink/
		$tmr6 = /(t)mrCheck/
		$tmr7 = /(t)mrCountdown/
		$tmr8 = /(t)mrCrazy/
		$tmr9 = /(t)mrDOS/
		$tmr10 = /(t)mrDoWork/
		$tmr11 = /(t)mrFocus/
		$tmr12 = /(t)mrGrabber/
		$tmr13 = /(t)mrInaktivitet/
		$tmr14 = /(t)mrInfoTO/
		$tmr15 = /(t)mrIntervalUpdate/
		$tmr16 = /(t)mrLiveLogger/
		$tmr17 = /(t)mrPersistant/
		$tmr18 = /(t)mrScreenshot/
		$tmr19 = /(t)mrSpara/
		$tmr20 = /(t)mrSprid/
		$tmr21 = /(t)mrTCP/
		$tmr22 = /(t)mrUDP/
		$tmr23 = /(t)mrWebHide/

	condition:
		10 of ($mod*) or 10 of ($tmr*)
}
