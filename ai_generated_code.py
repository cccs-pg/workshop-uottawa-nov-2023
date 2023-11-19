def fibonacci(n):
    # Check if n is 0 or negative
    if n <= 0:
        return "Invalid input"

    # Initialize the first two numbers in the sequence
    fib_seq = [0, 1]

    # Calculate the Fibonacci sequence
    for i in range(2, n):
        fib_seq.append(fib_seq[i-1] + fib_seq[i-2])

    return fib_seq

# Test the function with different input values
print(fibonacci(1))
print(fibonacci(2))
print(fibonacci(4))
print(fibonacci(8))
