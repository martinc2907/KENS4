x = $1;

while ./build/testTCP --gtest_filter="*Transfer*";
do
	echo "$x times test passed"
	((x++))
	# sleep 1;
done