import random

class Prime:

	# Sieve of Eratosthenes implementation
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
		print("there are " + str(count) + \
			" primes less than " + str(max))

	def pre_test(num, max):
		for test in range(3, max, 2):
			if num % test == 0:
				return False
		return True

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

	def generate_prime(num_digits):
		while True:
			num = random.SystemRandom().randint(
				pow(10, num_digits - 1), pow(10, num_digits))
			if (num % 2 != 0 and Prime.pre_test(num, 20001)
				and Prime.rabin_miller_test(num)):
				return num