import sys

def sieve(max):
	nums = list(range(3, max, 2))
	primes = [2]
	p = 3
	count = 0

	while nums:
		primes.append(nums[0])
		count += 1
		p = nums[0]
		for i in range(p, max, p):
			if i in nums:
				nums.remove(i)

	print(primes)
	print("there are " + str(count) + " primes less than " + str(max))

sieve(int(sys.argv[1]))