import sys
from termcolor import colored
def splitNthcharacter(text, i, n):
	split = ""
	for x in xrange(i,len(text), n):
		split += text[x]
	return split

def indexOfCoincidence(text):
	length = len(text)
	index = 0.0
	for x in xrange(97,123):
		character = chr(x)
		index += (text.count(character)*(text.count(character)-1))
	return (index / (length*(length-1)))

def guessKeyLength(cipher, low, high):
	print "Key\tIndex-Of-Coincidence"
	for x in xrange(low,high+1):
		mean=0.0
		for y in xrange(0,x):
			mean += indexOfCoincidence(splitNthcharacter(cipher, y, x))
		mean /= x
		print x,"\t",mean


def printFrequency(cipher, n):
	print "   |",
	for x in xrange(97,123):
		print chr(x), " |",
	print ""


	for x in xrange(0,n):
		sys.stdout.write("#")
		print x, "|",
		text = splitNthcharacter(cipher, x, n)
		#print text
		for y in xrange(97,123):
			if text.count(chr(y)) > 9:
				print text.count(chr(y)), "|",
			else:
				print text.count(chr(y)), " |",
		print ""

def caeserShift(cipher, index, size, shift):
	l = list(cipher)
	for x in xrange(index,len(cipher), size):
		l[x] = chr(97+(((ord(cipher[x])-97) + shift)%26))
	return "".join(l)

cipher="yvrwxrvmeegfdxgfzywtxzlvlqccbgnpptlqcttwvfadgukginvvgcwkrgcmqrqdogicxzpjmrbccghmuvajecibtfqtppmktptiwsjxvcebihuvajkgkmpenzrhvkkgoxpjhjlvzatlqtgpegtmchozapgfgmabvzapenzztkvpmumjfsvavvvekgjqxhpscabgwdpbvyycwyfphakgcfnccgirqwqitvlqpgffddirfpinpzrntpurditfkdmgrkdgikftfccjukckcggkkwplulpxgikftwkxlxmafdiagzlsbxzbjtnrlsmjvscbvpycwkertztzrnhhkftgckgdgkemjkeflhmkkstgvrqhxosjnmjzqipgernlkorwwcpmugqmcbugilxggkctghfpirpzltwqycgxdpyshrkcctekycwizttmqfsglgcttlvyghvqeqibvlrxhp"
print "indexOfCoincidence of original message :: ", indexOfCoincidence(cipher)
guessKeyLength(cipher, 2, 50)

#guessed key length is 5 because index of coincidence for multiples of 5 is maximum and closest to 0.067
keyLength = 5
printFrequency(cipher, keyLength)

for x in xrange(0,keyLength):
	print indexOfCoincidence(splitNthcharacter(cipher, x, keyLength)) 

cipher = caeserShift(cipher, 0, keyLength, 24)
cipher = caeserShift(cipher, 1, keyLength, 9)
cipher = caeserShift(cipher, 2, keyLength, 2)
cipher = caeserShift(cipher, 3, keyLength, 11)
cipher = caeserShift(cipher, 4, keyLength, 7)

for x in xrange(0,len(cipher)):
	if x % keyLength == 0:
		sys.stdout.write(" ")
#	if x%keyLength == 0 or x%keyLength == 3 or x%keyLength == 4 or x%keyLength == 2:
	sys.stdout.write(colored(cipher[x], 'red'))
	# else:
	# 	sys.stdout.write(cipher[x])

print "\n\n"