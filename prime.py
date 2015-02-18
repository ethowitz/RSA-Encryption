import sys, random

class Prime:

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
		print("there are " + str(count) + 
			" primes less than " + str(max))

	def rabin_miller_test(num, k=40):
		d = num - 1
		s = 0

		while d % 2 == 0:
			d = d // 2
			s += 1

		for i in range(k):
			witness = random.SystemRandom().randint(2, num - 2)
			x = pow(witness, d, num)
			if not (x == 1 or x == num - 1):
				for j in range(s - 1):
					x = (x ** 2) % num
					if x == 1:
						return False
					if x == num - 1:
						break
				if x != num - 1:
					return False
		return True