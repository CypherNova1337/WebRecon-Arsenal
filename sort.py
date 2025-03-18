# Read the word list from the file
with open('filterparam.txt, 'r') as file:
	lines = file.readlines()

# Sort the lines
lines.sort()

# Take the first 100,000 lines
lines = lines[:100000]

# Write the sorted list to a new file
with open('sorted_params_100000.txt', 'w') as file:
	file.writelines(lines)

#Credit: @Coffinxp
