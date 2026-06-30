#!/usr/bin/env python3
Ab='record'
Aa='target_actor_id'
AZ='scene_action'
AY='action_name'
AX='key.txt'
AW=RuntimeError
AV=enumerate
A9='type'
A8='raw_payload'
A7='c2s'
A6='platform_actor_id'
A5='scene_actor'
A4='speed'
A3='request'
A2='_decoded'
A1='move'
A0='content'
z='event_class'
y='dir'
x=print
p='opcode_name'
o='opcode_hex'
l='actor_id'
n='captured_at'
m='flow_id'
j='pos'
k=max
i=min
h=bool
a='s2c'
Z='status'
Y='to_rot'
X=list
W=SystemExit
U='direction'
T=True
S='seq'
R=''
P='to_pos'
O=bytearray
N='big'
M=False
L='opcode'
K=ValueError
J=str
H=Exception
F=bytes
E=int
D=dict
C=isinstance
B=len
A=None
import argparse as Ac,base64,bz2,datetime as Ad,json,logging as AA,struct,sys,time
from dataclasses import dataclass as q,field as b
from pathlib import Path as r
try:from Crypto.Cipher import AES
except ImportError as Ae:raise W('Error')from Ae
from scapy.all import AsyncSniffer as Af,PcapReader as Ag
from scapy.layers.inet import IP,TCP as Q
from scapy.layers.inet6 import IPv6
ERROR='Error'
Ah=r(__file__).resolve().parent
I=AA.getLogger(__name__)
I.addHandler(AA.NullHandler())
I.propagate=M
AB=b'3f'
f=21
Ai=range(1,32768)
AC=16777216
Aj=8388608
AD=600
Ak=256
Al=4098
Am=16403
AE=F(range(16))
DEFAULT_PORT=8195
Ba=Ah/AX
def An():return Ad.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def s(c,d):
	D=C=0;A=d
	while A<B(c):
		E=c[A];A+=1;D|=(E&127)<<C
		if E<128:return D,A
		C+=7
		if C>63:raise K(ERROR)
	raise K(ERROR)
def Ao(a):
	A=0;D=B(a)
	try:
		while A<D:
			G,A=s(a,A);C=G&7;E=G>>3
			if C==0:H,A=s(a,A);yield(E,C,H)
			elif C==2:
				F,A=s(a,A)
				if A+F>D:return
				yield(E,C,a[A:A+F]);A+=F
			elif C==1:
				if A+8>D:return
				yield(E,C,a[A:A+8]);A+=8
			elif C==5:
				if A+4>D:return
				yield(E,C,a[A:A+4]);A+=4
			else:return
	except K:return
def Ap(v):v&=4294967295;return v-4294967296 if v&2147483648 else v
Aq=b'tsf4g'
AF=6
Ar=22
def AG(a):
	if B(a)<AF:return M
	A=a[-1];return AF<=A<=Ar and B(a)>=A and a[-6:-1]==Aq
def As(a):return a[-1]if AG(a)else 0
AH=1044
AI=1043
AJ=307
AK=345
AL=864
AM=1000
AN=5605
At=frozenset({AH,AI,AJ,AK,AL,AM,AN})
c=A
Au='LRx4!F+o`-Q&|W~llA}>6`z0*6o2qPH{Y7S|Nr`64clwJVD8ObzyTEv&YN^9T&MsU07RmIR5ee@04b@pG8<3;0iXZ?4NoSCl^PIJ$^ZeTfEoip142y*8X7bMLrnk;0Q8tZAxMyzsp?{zLq?M{(?)><1P@b8a{!nDFaQaF0GI#>k|sg~&;&G1Pe4pYO#z9gsDwZ>z?1_)#YkphNXkKymOYsw)z6avs6a|#zfl`H1hnJS``majJQH^jP_U0*>DE7W>yCn}!Sjj1EA0F)Kv>cUGDFlltRWRQ+W5!vk_{qP(a3m^fs%j79U;Kwk>4oJyA({I((t6&dtD~3m%pcud%QOnmyQXbC{4w3lAkAS>D@HeOI1-xBymQv(=n`O-@%BlXLh(h@}ua4fQtM5em@I+564S<z5u@oGgTdLnTjl96BRK4Oh~#0;@Fe3Un@k$Ih{SJf@RS)lekD=sJe@6I|^rWGe+gYnQ10uD!a#7w(oB(jhHB^m`)=k)o$-6HJ6#U2)*xQ&f7bK3Ekal=+)fJgs@nnb2lR9M9Q#r6%ZpPArMyf@Uxb&L$f$ch>kVv_4r4V^V)z~HMB&HdTh%Yz@}@ZQ6xH@!eJe^Oh0xE>zd3Rzv)yyXh40HRZ$napYPbb{{h#>eA8ZSANzd|RSY%b^F+@GQ7$}hl-$kkjYpT3PdOSGbk3fLgQRr?QPV7YT$dfz_tI5@!}MH%C<MAFEJ=DPsWEC|`H?*awkSHK5nz-Y#{`I!AP`|fbkKrkTs06E2BLw4N~ohTQsC+HPazss_XG>ZLm=#r#j&-BvIWH!G|bafW|pzi$%tgP8*#PmjON@p>wJFW<rE1LKxBa>p@{^fDoGg?iYXcff%HPsnFUEGK_ikmBS}C~Q%KN42?YaCgn7N9hq!8yK&nt^6sP~0MN?H(RZL1HRaI40RaI40RaI40RYg@4vX59$Gg{JG!%!&55_>&fsH$=gsy>^~$pH32qJk)0^T5=K{`|1^+me!&iW`h_2ke7HnR3iSaX~?I!7}ALo>2H}9wLOMtE@T3Yc6*iGB}2+hjtN3ae!p+Gq1OM*i*|{siK_{VG#yq7bwV-6*``fljZ;jHTXirm}nsNr>Nu_180!KL^eH2D58%;K)<-2;^C792vPW{MPubvMyJ?a66S~2A5nJ9oeC(i_?TN4IS|TSw48p)CJPukpKgR~WioI%kRdyWB@&{gDYWNrFwRH3b~dlig;gEmjU5#oqR4Bk2_Qn{B^%(DH*9EF*zfL=5rM&mVR?)bsGXquQ`ZO-0ZP>ZlmS6V(zGc0;K?#U$N;8;AjzVKN{af49)zOh-1yHdR15?@`3Zp#O1jtb(Q76rC<jgq%H?)<$?-ZNbDf#uW^}Ac26tDMndX4Cvr9aP>i1gXe8DcG1p05$_4cgBfl$VKWDRTnAsHbNg8RGD)N0{k5vrg%>2;ypEIYo7o7QOc3x@OWjYg*f2E~fkjhQ$TzGTGd;jQiJ8*enY6E8fxFIWM7W1gU3ekmF3#$7^)xs?oTF>r&RhaAcvkaR~q@51mf(Ae!-99L=rL8?H~$Wty1FCbJ`F0IQWBXkC=MII|#!&I?`DGtjL+=yhfsjQ>7wZB<@8x}Xc1q2|#!{d4a29V#Df1AM4jFB)M^{)M_(gaD8L$K?7qr>(#G|K2a4;%ht5Zk;%i&+m2WB!hb#p;jhK9*i^+oSpnJ(FPEo+-uXbj5ie++cEe9JRSzie2NtFI{k0!3Ky*-Qscbz^VSsng$8M)CY!$w*>tY6qCGuPn6)}b2r1?hzO4nGAhO~!{phb8FY#Pq~K5op{5UNy0^u{E7)pOEe}A~aq5>C;%4}JW)*1minow3z>x_7&_*T*Xy|p%1uBIIhS4WrQz4ovC8=c8c1IhC!40dsHH+mUG)N;oBJ}~Lvj=T;3(b5>MM8}ZtstsMJ>?K#Yq)`4z!M1_1a+%$LN$+s7=sFJrCO^?YycMsWa?;Oqbo%rn-UbS0RaLPfeNl{OWP>kbAh@*XzP%LgbqwjY*diDSHMwN-Wra43Zivh22E=6!E(ME^8<%JBi{PMqH+j!5DF*kbm)HN&Hg1nFW}fS<+H=kuulDiJbcj8Ndm#04uW&s`glT_IEzU23PZfLH>T%}o(GAfqZeOzyMvwj^|R(+xw=CnZ)}zuXScR|iex!Uy`iO}I*2glaXY2lq&?e*w!#|UEAJePS92yB#&{d>q$q(PdJusj9GQlLT3+1;L|?usAcT&<^6Q{F$CjX0;z$a4d76N3-{fw0Ixn4_)3kY>0(UhogTu3-=5s{Hr<dwZ@J%*Nz+LBjPJmnu!?a8yA1>b^&Zp700EVl?%0>x6?vgdb!XW|>Vc%FRRj8oxEJA|BeWz*lo}uP)<6|!~31EuAt-<JV>S@=eh1~Qe;|c0@y};Y5_qice2yXGLLE+)n;T^ZG?D-XagNZnlox{qS!p(u2G<E~6Cb-}N2z?owi!+1`cEyV-l8C7@pm2~;#~L0Cu0Avf>;zy*nIVa26-A8<9>EO|HVJd}A_i57jg3d?03rrNG=aT?ZU(U{X8|1sqA<x+6b9tjydqYgf@+v99S6xL(h#Z&04an*EKaz9djqw6m<QStGPMk!SeZ|UnEHVjPQmd##`^&~faZ}A`Kum%4LO|J^L8T<4zU6F_ZYZ*!`cPM-hVLq0NcO^#Eux0h;r}^2nW_r;XAA3N)x>T3U*lQr*Wb`L+pM(pZ2(Ep$&@r1OwFKkC#A+rvv6l5I(RufxjM+RRlp#ZU1c{zo{buCJH(RrV~jXH_#B}Mo4%BNU%X7QwJ6mBG6W+7<FLaGsL1mg*n27g7z-`A#?7!22C@YTsHLF&8|YS1&ek;?tyQauyIHOz#u{rM$R}2s&7xd^y|2s)46tC2;L8)j@*TcVgW~WZ!B|YtCgX>64$X!Qw@q3!8#TgP<IwAS-xy(lcXmEGYYgMl1ND*yMVcB*$}emmnM)bmI@h0xC0j70l{R=OEX-YGUfzfGbcbcof)WW&!LIAd)ptCs-aPJi`rzdLanSB(!pT1O0+p+881?TW^E`QXi>nr-Qsd1V(N1#A2oykfM7?E<f~YcMJVgA?U2B1nuuH^nK?kbsmuu)h?1!&qm(I=mJ=BO<zrzmfSHM*;2Kc#xJYt|$1hNUhcKa1>t(Q`{UC&kAa0yVxSogPA25dDlRGrd_2e%j3D?jf9U_UZ+!+ruKMuk6X8Z}w85tDq2vA_`@w`NLo7{n;;J>c%;mJJmQ5lSW1T^}NXP&**xhAP$mLjK5Guot00PyMgpuXt+1s!R__!n|TI8cxXN|W{'
def AO():
	global c
	if c is A:
		try:B=base64.b85decode(Au);c=json.loads(bz2.decompress(B).decode('utf-8'))
		except H as C:raise W(ERROR)from C
	return c
def AP():
	A=AO().get('move_proto')
	if not C(A,D):raise W(ERROR)
	return A
def t(b):
	A=AO().get('row_cfg')
	if not C(A,D):raise W(ERROR)
	return A[b]
def AQ():return AP()['messages']
def Av():return AP()['opcodes']
def Aw(a):
	if not C(a,(F,O))or B(a)!=4:return
	return struct.unpack('<f',F(a))[0]
def Ax(a):
	if not C(a,(F,O)):return R
	return F(a).decode('utf-8',errors='ignore')
def Ay(a):a&=0xffffffffffffffff;return a-0x10000000000000000 if a&0x8000000000000000 else a
def Az(d,b,e,c):
	if c:d.setdefault(b,[]).append(e);return
	if b not in d:d[b]=e;return
	A=d[b]
	if C(A,X):A.append(e)
	elif A!=e:d[b]=[A,e]
def A_(a,d,c):
	B=AQ()
	if a=='u':return c
	if a=='i':return Ap(E(c))
	if a=='q':return Ay(E(c))
	if a=='b':return h(c)
	if a=='f':return Aw(c)if d==5 else A
	if a=='x':return F(c).hex()if C(c,(F,O))else c
	if a=='s':
		if C(c,(F,O)):return Ax(c)
		return J(c)
	if a in B and C(c,(F,O)):return AR(a,F(c))
def AR(f,a):
	E=AQ().get(f)
	if not C(E,D):return{}
	F={}
	for(K,L,M)in Ao(a):
		G=E.get(J(K))
		if not G:continue
		N,B=G;H=B.startswith('*');O=B[1:]if H else B;I=A_(O,L,M)
		if I is A:continue
		Az(F,N,I,H)
	return F
def u(a):return Av().get(J(E(a)),R)
def B0(d,a):
	A=u(d)
	if not A:return
	B=As(a);C=a[:-B]if B else a;return AR(A,C)
def B1(c,a):
	try:return B0(c,a),R
	except H as B:return A,J(B)
def v(a):
	if C(a,D)and C(a.get(j),D):return a[j]
	return{}
def w(a):
	if C(a,D)and C(a.get(y),D):return a[y]
	return{}
def B2(a):
	B='base'
	for E in('avatar','npc','monster'):
		A=a.get(E)
		if C(A,D)and C(A.get(B),D):return A[B]
	return{}
def G(j,ri,l,b,h,f):f=f if C(f,D)else{};j.append({AY:b,z:h or A1,U:l.get(U),L:l.get(L),S:l.get(S),m:l.get(m),n:l.get(n),A0:f})
def B3(f):
	B=E(f.get(L,0)or 0);A=f.get(A2)
	if not C(A,D):return
	if B==AH:yield A
	elif B==AI:
		for F in A.get('acts')or[]:
			if C(F,D):yield F
def V(b):A=b.get(A2);return A if C(A,D)else{}
def B4(f,e,d,b):G(b,f,e,'zone_scene_move_req',A3,V(d))
def B5(g,f,e,c):E='to_point';A=V(e);B=A.get(E)if C(A.get(E),D)else{};G(c,g,f,'zone_scene_interact_move_req',A3,{P:v(B),Y:w(B),**A})
def B6(d,c,b,a):G(a,d,c,'zone_scene_sync_player_status_req',Z,V(b))
def B7(d,c,b,a):G(a,d,c,'zone_scene_change_move_mode_req',Z,V(b))
def B8(e,d,c,b):A=V(c);G(b,e,d,'zone_scene_relation_travel_together_sync_req',A3,{P:A.get('report_pos'),A4:A.get('pos_diff'),**A})
B9={AJ:B4,AM:B5,AK:B6,AL:B7,AN:B8}
def BA(d,ri,e,a):
	A='client_move';B=a.get(A)
	if C(B,D):G(d,ri,e,A,A,B)
def BB(e,ri,h,a):
	E='server_move';A=a.get(E)
	if not C(A,D):return
	I=A.get('to_pos_list')or[];J=A.get('to_time_list')or[];K=A.get('to_dir_list')or[]
	if C(I,X)and I:
		for(F,L)in AV(I):
			H=D(A);H[P]=L if C(L,D)else{}
			if F<B(J):H['time_stamp']=J[F]
			if F<B(K):H['custom_mode']=K[F]
			G(e,ri,h,E,E,H)
		return
	G(e,ri,h,E,E,A)
def BC(e,ri,i,a):
	for(E,F,H)in t('simple_actions'):
		A=a.get(E)
		if not C(A,D):continue
		B=D(A)
		if F:B[P]=A.get(F)
		if H:B[Y]=A.get(H)
		G(e,ri,i,E,AZ,B)
def BD(e,ri,i,a):
	for(B,E)in t('point_actions'):
		A=a.get(B)
		if not C(A,D):continue
		F=A.get(E)if C(A.get(E),D)else{};G(e,ri,i,B,AZ,{P:v(F),Y:w(F),**A})
def BE(f,ri,h,a):
	H='actor_enter';B=a.get(H)
	if not C(B,D):return
	for E in B.get('actors')or[]:
		if not C(E,D):continue
		A=B2(E);F=A.get('pt')if C(A.get('pt'),D)else{};G(f,ri,h,H,A5,{l:A.get(l),Aa:A.get('logic_id'),A6:A.get(A6),P:v(F),Y:w(F),**A})
def BF(e,ri,f,a):
	B='actor_leave';A=a.get(B)
	if not C(A,D):return
	for E in A.get('actor_ids')or[]:G(e,ri,f,B,A5,{l:E})
def BG(d,ri,f,a):
	B='actor_num';A=a.get(B)
	if C(A,D):G(d,ri,f,B,A5,{P:A.get(j),**A})
def BH(f,ri,g,a):
	for(B,E)in t('status_actions'):
		A=a.get(B)
		if C(A,D):G(f,ri,g,E,Z,A)
BI=BA,BB,BC,BD,BE,BF,BG,BH
def BJ(o,n,l):
	B=l.get(Ab)if C(l,D)else A
	if not C(B,D):return[]
	G=E(B.get(L,0)or 0)
	if G not in At:return[]
	F=[];H=B9.get(G)
	if H is not A:H(o,n,B,F);return F
	for K in B3(B):
		I=K.get('acts')
		if not C(I,X):continue
		for J in I:
			if C(J,D):
				for M in BI:M(F,o,n,J)
	return F
def BK(f):
	A=f.strip();C=ERROR
	if B(A)==16:
		try:return A.encode('ascii')
		except UnicodeEncodeError as E:raise K(C)from E
	D=R.join(A for A in A if A in'0123456789abcdefABCDEF')
	if B(D)==32:return F.fromhex(D)
	raise K(C)
def BL(b,a):
	if B(a)<16:raise K(ERROR)
	if B(a)%16!=0:raise K(ERROR)
	return AE,AES.new(b,AES.MODE_CBC,AE).decrypt(a)
def BM(a):
	if B(a)<16:raise K(ERROR)
	return a[16:]
def AS(a,b):return a.haslayer(Q)and(E(a[Q].sport)==b or E(a[Q].dport)==b)
def BN(b):
	for A in(IP,IPv6):
		if b.haslayer(A):B=b[A];return B.src,B.dst
def BO(c,d):
	G=BN(c)
	if G is A or not c.haslayer(Q):return
	D,F=G;H=c[Q];B,C=E(H.sport),E(H.dport)
	if B==d:return F,a,C,D,B,f"{D}:{B}->{F}:{C}"
	if C==d:return D,A7,B,F,C,f"{F}:{C}->{D}:{B}"
@q
class BP:di:J;cm:E;sq:E;he:F;bd:F
def BQ(c,e):
	if e+f>B(c):return
	C=E.from_bytes(c[e+6:e+8],N);A=E.from_bytes(c[e+13:e+17],N);D=E.from_bytes(c[e+17:e+21],N)
	if C not in Ai or A<f or A+D>4194304:return
	F=E.from_bytes(c[e+9:e+13],N);return C,F,A,D
def BR(c,d,m):
	G=[];C=m;H=B(c)
	while C+f<=H:
		if c[C:C+2]!=AB:
			I=c.find(AB,C+1)
			if I<0:break
			C=I;continue
		J=BQ(c,C)
		if J is A:C+=2;continue
		K,L,D,M=J;E=D+M
		if C+E>H:break
		G.append(BP(di=d,cm=K,sq=L,he=F(c[C+f:C+D]),bd=F(c[C+D:C+E])));C+=E
	return G,C
@q
class d:
	di:J;bu:O=b(default_factory=O);po:E=0;bs:E|A=A;ns:E|A=A;pe:D[E,F]=b(default_factory=D);pb:E=0
	def feed(C,e,c):
		if not c:return[]
		if C.bs is A:C.bs=e;C.bu.extend(c);C.ns=e+B(c)
		else:C._ingest_segment(e,c)
		if B(C.bu)>AC:C._trim_buffer()
		E,F=BR(C.bu,C.di,C.po);C.po=F
		if C.po>=65536 and C.po>B(C.bu)//2:
			D=C.po;del C.bu[:D]
			if C.bs is not A:C.bs+=D
			C.po=0
		return E
	def _ingest_segment(C,j,g):
		assert C.bs is not A;assert C.ns is not A;G=j+B(g)
		if j<C.bs:
			if G<C.bs:I.debug('DirectionState[%s] dropping old segment seq=%d end=%d base=%d',C.di,j,G,C.bs);return
			H=C.bs-j
			if H>0:C.bu=O(g[:H])+C.bu;C.bs=j;C.po+=H
			if G<=C.ns:return
			g=g[C.ns-j:];j=C.ns
			if not g:return
		if j<=C.ns:
			E=j-C.bs;D=C.ns-j
			if D>0 and E>=0:
				D=i(D,B(g));J=F(C.bu[E:E+D]);K=g[:D]
				if J!=K:
					if E<C.po:I.debug(ERROR);return
					L=I.debug if J and all(A==0 for A in J)else I.warning;L(ERROR);del C.bu[E:];C.bu.extend(g);C.ns=j+B(g);C.po=i(C.po,E);C._drain_pending();return
			if D>=B(g):return
			C.bu.extend(g[D:]);C.ns+=B(g)-D;C._drain_pending();return
		C._store_pending(j,g)
	def _store_pending(C,j,h):
		F=j+B(h)
		for(D,G)in X(C.pe.items()):
			H=D+B(G)
			if D<=j and H>=F:return
			if j<=D and F>=H:C.pb-=B(G);del C.pe[D]
		E=C.pe.get(j)
		if E is not A:
			if B(E)>=B(h):return
			C.pb-=B(E)
		C.pe[j]=h;C.pb+=B(h)
		while C.pb>Aj and C.pe:J=k(C.pe);K=C.pe.pop(J);C.pb-=B(K);I.warning(ERROR)
	def _drain_pending(C):
		assert C.ns is not A
		while T:
			F=[A for A in C.pe if A<=C.ns]
			if not F:return
			G=i(F);D=C.pe.pop(G);C.pb-=B(D);E=C.ns-G
			if E>=B(D):continue
			C.bu.extend(D[E:]);C.ns+=B(D)-E
	def _trim_buffer(C):
		if not C.bu:return
		I.warning(ERROR);E=AC//2
		if C.po>0:D=i(C.po,k(0,B(C.bu)-E))
		else:D=k(0,B(C.bu)-E)
		if D<=0:return
		del C.bu[:D];C.po=k(0,C.po-D)
		if C.bs is not A:C.bs+=D
@q
class BS:fi:J;ci:J;cp:E;si:J;sp:E;ls:float=.0;c2:d=b(default_factory=lambda:d(A7));s2:d=b(default_factory=lambda:d(a));ky:F|A=A
def BT(b,c):
	if B(b)<10 or b[4:6]!=b'U\xaa':return
	A=E.from_bytes(b[0:4],N)
	if A<=0 or A>65535:return
	C=E.from_bytes(b[6:10],N);return{S:c,U:a,L:A,o:f"0x{A:04X}",p:u(A),'subtype':C,A8:b[10:]}
def BU(b):
	A=b&65535
	if b>65535 and b>>16==1 and A:return A,T
	return b,M
def BV(c,g):
	if B(c)<14 or not AG(c):return
	D=E.from_bytes(c[0:4],N);A=E.from_bytes(c[4:8],N)
	if A<=0 or A>>16 not in{0,1}or A&65535==0:return
	C,F=BU(A);G=E.from_bytes(c[10:14],N);return{S:g,U:A7,L:C,o:f"0x{C:04X}",p:u(C),'raw_opcode':A,'raw_opcode_hex':f"0x{A:08X}",'opcode_normalized':F,'prefix_u32':D,'stream_tag':c[8:10].hex(),'req_seq':G,A8:c[14:]}
class BW:
	def __init__(A,*,c,g,b,d,e=R,a=()):A.po=c;A.sl=g;A.kf=b;A.pk=d;A.ck=d;A.ps=e;A.al=a;A.ss=M;A.pc=0;A.kh=0;A.dw=0;A.bf=0;A.pr=0;A.fr=0;A.de=0;A.le=0;A.fe=0;A.fl={};A.wk=M
	def stats(C):return{'packets':C.pc,'key_hits':C.kh,'rows':C.dw,'parsed':C.pr,'failed':C.fr,'decode_errors':C.de,'listener_errors':C.le,'has_key':C.ck is not A,'flows':B(C.fl),'flow_expirations':C.fe,'flow_ttl_seconds':AD}
	def _cleanup_flows(A,c):
		C=[B for(B,A)in A.fl.items()if A.ls and c-A.ls>AD]
		for D in C:del A.fl[D]
		if C:A.fe+=B(C)
	def process_packet(B,l,j=A):
		if not AS(l,B.po):return
		B.pc+=1;D=time.time()
		if B.pc%Ak==0:B._cleanup_flows(D)
		G=F(l[Q].payload)
		if not G:return
		H=BO(l,B.po)
		if H is A:return
		I,N,J,K,L,O=H;M=I,J,K,L;C=B.fl.get(M)
		if C is A:
			C=BS(fi=O,ci=I,cp=J,si=K,sp=L,ls=D,ky=B.pk);B.fl[M]=C;B.sl.log(f"[flow] new flow={C.fi}")
			if B.pk:B.sl.log('Key')
		else:C.ls=D
		P=C.s2 if N==a else C.c2
		for R in P.feed(E(l[Q].seq),G):B._handle_be21(C,R,l,j)
	def _handle_be21(C,f,b,j,g):
		if b.cm==Al and B(b.he)>=18:
			E=b.he[2:18]
			if f.ky!=E:f.ky=E;C.ck=E;C.kh+=1;W=' refreshed'if C.pk is not A else R;C.sl.log('Key')
		if b.cm!=Am or not C.al:return
		C.bf+=1
		if f.ky is A:return
		try:X,J=BL(f.ky,b.bd);F=BM(J)
		except K as M:
			C.fr+=1;I.warning(ERROR)
			if C.pk is not A and not C.wk:C.wk=T;Y=C.ps or'preset key';C.sl.log(ERROR)
			return
		if b.di==a:D=BT(F,b.sq)
		else:D=BV(F,b.sq)
		if D is A:C.fr+=1;return
		C.pr+=1;G,N=B1(D[L],D[A8])
		if N:C.de+=1;C.fr+=1;I.debug(ERROR);return
		if G is A:return
		D[A2]=G;O={n:An(),m:f.fi,U:b.di,S:b.sq,L:D[L],o:D[o],p:D[p]};P=C.dw;C.dw+=1;Q={Ab:D}
		for V in C.al:
			try:V.handle(P,O,Q)
			except H as M:C.le+=1;C.sl.log(ERROR);I.exception(ERROR)
class BX:
	def __init__(A,cb=A):A.cb=cb
	def log(A,b):0
	def close(A):0
def parse_key(value):
	B=value
	if B is A or C(B,F):return B
	try:return BK(J(B))
	except H as D:raise K(ERROR)from D
def e(b):
	if not C(b,D):return
	B={B:b.get(B)for B in'xyz'if b.get(B)is not A};return B or A
def compact_event(event):B=event;E=B.get(A0)if C(B.get(A0),D)else{};F={A9:A1,'kind':B.get(AY)or B.get(z)or A1,'class':B.get(z),y:B.get(U),'op':B.get(L),S:B.get(S),'flow':B.get(m),'time':B.get(n),'actor':E.get(l),'target':E.get(Aa),'platform':E.get(A6),j:e(E.get(P)),'rot':e(E.get(Y)),A4:e(E.get(A4)),'acc':e(E.get('acceleration')),'mode':E.get('move_mode'),Z:E.get(Z)};return{C:B for(C,B)in F.items()if B is not A}
def g(cb,a):
	if cb is A:return
	try:cb({A9:a})
	except H:pass
class BY:
	def __init__(A,a):A.owner=a
	def handle(A,d,c,b):
		try:
			for B in BJ(d,c,b):A.owner._emit(compact_event(B))
		except H:g(A.owner.on_status,ERROR)
class RkppLite:
	def __init__(A,key=A,port=DEFAULT_PORT,on_event=A,on_status=A):B=on_status;A.on_event=on_event;A.on_status=B;A._batch=[];C=parse_key(key);A._sink=BY(A);A._analyzer=BW(c=E(port),g=BX(B),b=r(__file__).with_name(AX),d=C,e='api'if C else R,a=(A._sink,))
	def _emit(B,a):
		B._batch.append(a)
		if B.on_event is not A:
			try:B.on_event(a)
			except H:g(B.on_status,ERROR)
	def feed_packet(A,packet,frame_no=A):
		A._batch=[]
		try:A._analyzer.process_packet(packet,frame_no)
		except H:g(A.on_status,ERROR)
		return X(A._batch)
	def stats(A):return A._analyzer.stats()
	def stop(A):A._analyzer.ss=T
	@property
	def has_key(a):return a._analyzer.ck is not A
def events_from_pcap(path,key=A,port=DEFAULT_PORT,on_status=A):
	A=RkppLite(key=key,port=port,on_status=on_status)
	try:
		with Ag(J(path))as B:
			for(C,D)in AV(B,1):
				for E in A.feed_packet(D,C):yield E
	except H as F:raise AW(ERROR)from F
def BZ(a):
	if a is A:return M
	if callable(a):return h(a())
	if hasattr(a,'is_set'):return h(a.is_set())
	return h(a)
def run_live(iface=A,key=A,port=DEFAULT_PORT,on_event=A,on_status=A,no_bpf=M,stop=A):
	D=on_status;B=port;C=RkppLite(key=key,port=B,on_event=on_event,on_status=D);G=A if no_bpf else f"tcp port {E(B)}";F=Af(iface=iface,store=M,prn=C.feed_packet,lfilter=lambda packet:AS(packet,E(B)),filter=G)
	try:
		F.start()
		while not BZ(stop):time.sleep(.25)
	except KeyboardInterrupt:pass
	except H as I:g(D,ERROR);raise AW(ERROR)from I
	finally:
		C.stop()
		try:F.stop()
		except H:pass
	return C.stats()
def AT(a):
	if a.get(A9)==ERROR:x(ERROR,file=sys.stderr,flush=T)
def AU(a):x(json.dumps(a,ensure_ascii=M,separators=(',',':')),flush=T)
def main(argv=A):
	B=Ac.ArgumentParser(description='rmls');B.add_argument('--iface');B.add_argument('--port',type=E,default=DEFAULT_PORT);B.add_argument('--key');B.add_argument('--read-pcap',type=r);B.add_argument('--no-bpf',action='store_true');A=B.parse_args(argv)
	try:
		if A.read_pcap:
			for C in events_from_pcap(A.read_pcap,key=A.key,port=A.port,on_status=AT):AU(C)
		else:run_live(iface=A.iface,key=A.key,port=A.port,no_bpf=A.no_bpf,on_event=AU,on_status=AT)
		return 0
	except H:x(ERROR,file=sys.stderr,flush=T);return 1
if __name__=='__main__':raise W(main())