import "pe"

rule cobalt_strike_dll21_5426
{
	meta:
		description = "files - 21.dll"
		author = "TheDFIRReport"
		date = "2021-07-25"
		hash1 = "96a74d4c951d3de30dbdaadceee0956682a37fcbbc7005d2e3bbd270fbd17c98"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AWAVAUATVWUSH" fullword ascii
		$s2 = "UAWAVVWSPH" fullword ascii
		$s3 = "AWAVAUATVWUSPE" fullword ascii
		$s4 = "UAWAVATVWSH" fullword ascii
		$s5 = "AWAVVWUSH" fullword ascii
		$s6 = "UAWAVAUATVWSH" fullword ascii
		$s7 = "AVVWSH" fullword ascii
		$s8 = "m1t6h/o*i-j2p2g7i0r.q6j3p,j2l2s7p/s9j-q0f9f,i7r2g1h*i8r5h7g/q9j4h*o7i4r9f7f3g*p/q7o1e5n8m1q4n.e+n0i*r/i*k2q-g0p-n+q7l3s6h-h6j*q/" ascii
		$s9 = "s-e6m/f-g*j.i8p1g6j*i,o1s9o5f8r-p1l1k4o9n9l-s7q8g+n,f4t0q,f6n9q5s5e6i-f*e6q-r6g8s1o6r0k+h6p9i4f6p4s6l,g0p1j6l4s1l4h2f,s9p8t5t/g6" ascii
		$s10 = "o1s1s9i2s.f1g5l6g5o2k8h*e9j2o3k0j1f+n,k9h5l*e8p*s2k5r3j-f5o-f,g+e*s-e9h7e.t0e-h3e2t1f8j5k/m9p6n/j3h9e1k3h.t6h2g1p.l*q8o*t9l6p4s." ascii
		$s11 = "k7s9g7m5k4s5o3h6k.s1p.h9k.s-o8e*f5n9r,l4f-s5k3p2f/n1r.i*f*n-p4s3e7m9p2t/e3m5g1s9e0m1q/j*e*m-r*i+h.p9s2f6h-p5s6e2h8p1s*j.h3p-s.h0" ascii
		$s12 = "k9g9o0t1s4k*k*h.s-p-k.h-m1k*f4h0j7f6n,i5g-n3h+l3n1j7j0e*n5r6r-i9i/e1q4m6i3e2o8j9h9e0m.r-i9m*t4j/r.o*l8m4i.t5l,g-h0p6f7l+p-l3l,g." ascii
		$s13 = "s6k9n/j.s4s5g2p6s.k1t/j6s,s-g*p.n6f9m/g.n4n5j2q6n.f1p/g6n,n-j*q.m6e9o/h.m4m5i2r6m.e1p/h6m,m-i*r.p6h9m/e.p4p5l2s6p.h1l/e7p,p-l*s." ascii
		$s14 = "r4k7g8t-k4o6m,o1s1k.k1s6o,h8k-s4j8q*m+f/i*q/f3m-r5j2n0f0i*q0m/e0j5q7n5f4j7q3n7f1m4g2s,g5s5l9h7s9p1o.t8k5r-j3t.k8h1t6r7m-l5h5t1l*" ascii
		$s15 = "k8s9n7o9k5s5o9m2k0s1m3m.k,s-n+o-f9n9t+t6f4n5o6t2f0n1s/r1f-n-o.t*e8m9i-s6e4m5t3q5e1m1i5s.e,m-k0s*h8p9q7t9h5p5j8r2h0p1h+r.h,p-q+t-" ascii
		$s16 = "o9g6g0l0s1e6h4p-g6s9s9p1m1k*s3l-t5s.f8m5r5f6n+i2j8f*h,p5j2r.h0h1q9i6e8r-i*n8m-r5s-l.i8f2i1k.o4n1t9l6l0g,p9j6f,g.l-j*n0o-t-l*p5s-" ascii
		$s17 = "t8n2i3e0i,l.i7i9e8r1j7o0n3i9j0m3m-l6e6s9r*l6s5h4t6n7o*k.r1f+r4l/q9g7i3o.m+t9q*g/j0h0e1n*m3i,h.e4n3i5n-r9g1h2k6m7j,e,p3p+h2o4f/h4" ascii
		$s18 = "[_^A^A_]" fullword ascii
		$s19 = "k9s9f+j*k3s5o-j/k/s1h/p5k-s-o7j7f7n9t/g+f3n5q/r8f1n1t7g3f+n-p.g8e7m9s3q4e5m5o+h0e/m1g-h4e+m-m+q0h9p9f/e,h3p5l6e1h/p1o7t,h-p-k+f5" ascii
		$s20 = "g8s9j0t4o,t+n3t1g0k9k1t,o5s0n+t9n6j+o0q2i4j6r1i3f,g+j2h1f2r1n-e9m,i2i7f3q4m-n7n4m.r.e1s*j,m5p/n0n6s8p9g/o7l3t+g.m.q.l7g6t,e-o/q." ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 8 of them
}
