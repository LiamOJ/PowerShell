$alph = "abcdefghijklmnopqrstuvwxyz".ToLower()

$key = "botnet".ToLower()

$coded_message = "TLEQIL ZVL RCO-1970U".ToLower()
#$coded_message = "the previous unit outlined how data can be encrypted so that it cannot be viewed by anyone that it was not intended from. with private-key encryption, bob and alice use the same secret key to encrypt and decrypt the message. then, using a key interchange method such as diffie-hellman, bob and alice can generate the same secret key, even if eve is listening to their communications. with public-key encryption, bob and alice do not have the same problem, as alice can advertise her public key so that bob can use it to encrypt communications to her. the only key that can decrypt the communications is aliceÆs private key (which, hopefully, eve cannot get hold off). we now, though, have four further problems:- how do we know that it was really bob who sent the data, as anyone can get aliceÆs public key, and thus pretend to be bob? - how can we tell that the message has not been tampered with? - how does bob distribute his public key to alice, without having to post it onto a web site or for bob to be on-line when alice reads the message? - who can we really trust to properly authenticate bob? obviously we canÆt trust bob to authenticate that he really is bob. these questions will be answered in this unit, as we will look at the usage of hashing to finger-print data, and then how bobÆs private key can be used to authenticate himself. finally, it will look at the way that a public key can be distributed, using digital certificates, which can carry encryption key. this chapter will show the importance of authentication and assurance, along with confidentiality (figure 4.1), and the usage of biometrics.".ToLower()

$string = ""

$spaces = 0

for ($counter = 0; $counter -lt $coded_message.Length; $counter++ ) {
    
    if ($alph.IndexOf($coded_message[$counter]) -eq -1) { $string += $coded_message[$counter]; $spaces++; continue }
    $string += $alph[$alph.IndexOf($coded_message[$counter]) - $alph.IndexOf($key[($counter - $spaces) % $key.Length])]

}

$string

#abcdefghijklmnopqrstuvwxyz
#klmnopqrstuvwxyzabcdefghij

# to decrypt
# letter to decode.index - key.index % key.length

# To encrypt
# (Letter to encode.index + key.index) % alpha.length
# z = 25, k = 10, alph length = 26
# (25 + 10) % 26 = 9
# j.index = 9