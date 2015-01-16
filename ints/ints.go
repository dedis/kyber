package ints

// Max returns the maximum of x and y.
func Max(x,y int) int {
	if x > y {
		return x
	}
	return y
}

// Min returns the minimum of x and y.
func Min(x,y int) int {
	if x < y {
		return x
	}
	return y
}

// Abs returns |x|, the absolute value of x.
func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Sign returns:
// 
//	-1 if x <  0
//	 0 if x == 0
//	+1 if x >  0
//
func Sign(x int) int {
	if x < 0 {
		return -1
	} else if x > 0 {
		return 1
	}
	return 0
}

