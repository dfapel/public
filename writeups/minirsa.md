About miniRSA and how its solution can(not) be used to break RSA
======

Overview
--------
The picoctf challenge miniRSA is a crypto challenge that provides a textbook RSA instance and requires the player to obtain the original message.

Problem instance
-------------
```
N: 29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673
e: 3

ciphertext (c): 2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783537203207707757768473109845162808575425972525116337319108047893250549462147185741761825125 
```
The modulus `m` is of size 2048bit (therefore quite difficult to factor), and the public key `e` of 3 is quite small, but 3 is no uncommon value for `e`. However, choosing such a small public key in this case is fatal. The RSA algorithm works as follows:
```
(N, e, d) <- GenRSA
Enc(m, e) := m^e mod N
Dec(c, d) := m^d mod N
```

With the "overwrap" because of the modulus, the encryption function cannot be easily reverted by applying the `e`-th root to the ciphertext. However, because the public key was chosen to be 3 and the ciphertext seems to be rather small (compared to the modulus), we have all reason to assume that no "overwrap" occurred in the encryption process.

This means we can just take the cubic root of the given ciphertext to obtain the original message. The root operation on such large integers can be done by the gmpy2 library, as seen in the following code snippet:

```py
import gmpy2

e = 3
c = 2205316413931134031074603746928247799030155221252519872649649212867614751848436763801274360463406171277838056821437115883619169702963504606017565783537203207707757768473109845162808575425972525116337319108047893250549462147185741761825125

ret = gmpy2.iroot(c, e)
if ret[1]: # this is an exact value
        hex = format(ret[0], 'x')
        print(f"Message hex: {hex}")
        print(bytes.fromhex(hex))
else:
        print("No exact root found")
```
which yields the flag `picoCTF{n33d_a_lArg3r_e_606ce004}`. We don't need to know the value of `N` at all, which is quite funny. 

There is another challenge in picoctf called the same but with a space in between (mini RSA). This time, the ciphertext has roughly the same size as the modulus, so the approach above will no longer work. However, we got the hint that the message `m` is small enough such that `m ** 3` is only slightly larger than `N`. How much larger, we don't know, but we can assume there are only a few, exhaustively searchable "overwrappings". An overwrapping corresponds to adding the modulus to the ciphertext. By doing this iteratively, and checking if there exists an exact cubic root, we will eventually find the original message. This can be done with the following script:

```py
N = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
e = 3

c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808147130204332030239454609548193370732857240300019596815816006860639254992255194738107991811397196500685989396810773222940007523267032630601449381770324467476670441511297695830038371195786166055669921467988355155696963689199852044947912413082022187178952733134865103084455914904057821890898745653261258346107276390058792338949223415878232277034434046142510780902482500716765933896331360282637705554071922268580430157241598567522324772752885039646885713317810775113741411461898837845999905524246804112266440620557624165618470709586812253893125417659761396612984740891016230905299327084673080946823376058367658665796414168107502482827882764000030048859751949099453053128663379477059252309685864790106


for i in range(0, 10000):
        ret = gmpy2.iroot(c + i * N, e)
        if ret[1]: # this is an exact value
                hex = format(ret[0], 'x')
                print(f"Message hex: {hex} found after {i} iterations")
                print(bytes.fromhex(hex))
                break
else:
        print("No exact root found, maybe increase search range?")
```
The script terminated after 3533 iterations and yields the flag `picoCTF{e_sh0u1d_b3_lArg3r_7adb35b1}` (prepended with some space characters).

Lessons learned
---------------
- First of all: Don't ever use plain, textbook RSA
- Secondly: If `e` and `m` are both chosen to be very small, such that `m ** e` is of comparable size of `N`, we can decrypt the ciphertext without knowing the private key. The choice of `e = 3` is actually quite common, and this itself is not problematic.

Further thoughts
----------------
_The following section is a excursion to some cool stuff one can (or cannot, as we will see) build on top of the solution to this challenge. It has nothing to do with the challenge itself_

We can now apply some theoretic ideas to these challenges. We have constructed an efficient algorithm that, given a RSA instance `(modulus, public key, ciphertext) = (N, 3, c)`, can efficiently decrypt all ciphertexts `c` for which the inequality `c ** 3 < N` holds. This algorithm, call it `A`, therefore succeeds in decrypting `c` with probability 1 (=always) if `c` is small enough, and with probability 0 (=never) otherwise (assume it returns some failure symbol in this case). We now can construct another algorithm, call it `A'` that uses `A` to decrypt any ciphertext `c`. How can this be done?

First, `A'` picks a random group element `y`, and calculates its encryption (i.e., by raising it to the power of three). It then multiplies this with the ciphertext we want to decrypt, call the product `c'`. `A` is then asked for decryption of `c'`. If this succeeds, the inverse of `y` is calculated, multiplied with the decryption and returned. The following pseudocode shows `A'`: 

```
A'(N, e, c) {
    while true:
        pick y randomly from the group      # uniformly distributed 
        calculate y' = y ** e mod N         # is uniformly distributed by lemma 2
        calculate c' = c * y' mod N         # is uniformly distributed by lemma 1
        
        m = A(N, e, c')                     # asking A for decryption of a uniformly distributed ciphertext
        if m != fail:
            break
    
    calculate y^{-1} (the inverse of y)
    return m * y^{-1} mod N
}
```

Before arguing about correctness, we need two lemmas to reason about the probability distributions:
1. Let `a` be a (fixed) element in a group. Let `b` be a uniform random element in the group. Then, `a * b` has uniform distribution. This is because multiplication with `a` just permutes the group, yielding the same distribution as before. (By uniqueness of inverse elements, we get that there cannot be two different `b'` and `b''` such that `a * b' = a * b''`. By closure, we get that there must exist a `a * b` element. By combining these two, we get that the operation is a bijection, and a bijection on itself is called a permutation)
2. Raising a uniform distributed element `c` in the group with the public key `e` yields a uniform distributed result. This is because the operation again is a permutation, since it is invertible (by applying the "proper" decryption, i.e., raising the result to the private key)

By combining these two lemmas, we can see that despite that we ask `A'` for the decryption of a fixed ciphertext `c`, we can use `A` to find this decryption even though the algorithm `A` is not capable of doing this. This is because the queried cyphertext `c'` has uniform distribution. 

Correctness argument: Assuming `m` was the message returned by `A`, we have that it satisfies `m = (c')^d = (c * y')^d = c^d * y^(ed) = c^d * y`. `A'` returns `m * y^(-1) = c^d * y * y^(-1) = c^d`, which is the original message.

This seems to be to good to be true, right? Well, there is a simple snag: The probability that `A` finds a valid decryption decreases exponentially in the bitlength of `N`. There are around `2^n` possible ciphertexts, but only around `2^(n/3)` can be solved by `A`, yielding a success probability of `2^(-2n/3)`. Therefore, `A'` will just not terminate in reasonable time for large `n`.

The principle behind this is called random self-reducibility. If there would exist an algorithm `A` that can decrypt a "large enough" fraction of ciphertexts, then one could construct another algorithm `A'` just like we did now to break the encryption schema. But "large enough" means that id does not decrease exponentially in the security parameter, so this "edge-case attack" on RSA is not enough to attack RSA encryption with a public key of 3 in general.

References and collaboration
----------------------------
- Link to the first miniRSA problem: https://play.picoctf.org/practice/challenge/73
- Link to the second miniRSA problem: https://play.picoctf.org/practice/challenge/188
- The "further thoughts" section was inspired by a discussion with colleagues in crypto class.