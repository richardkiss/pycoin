
class NoSuchPointError(ValueError):
    pass


class Point(tuple):
    """A point on an elliptic curve. Altering x and y is forbidden,
     but they can be read by the x() and y() methods."""
    def __new__(self, x, y, curve):
        return tuple.__new__(self, (x, y))

    def __init__(self, x, y, curve):
        self._curve = curve
        super(Point, self).__init__()

    def check_on_curve(self):
        if not self._curve.check_point(self):
            raise NoSuchPointError('({},{}) is not on the curve {}'.format(*self, self._curve))

    def __add__(self, other):
        """Add one point to another point."""
        return self._curve.add(self, other)

    def __mul__(self, e):
        """Multiply a point by an integer."""
        return self._curve.multiply(self, e)

    def __rmul__(self, other):
        """Multiply a point by an integer."""
        return self * other

    def double(self):
        return self._curve.double(self)

    def x(self):
        return self[0]

    def y(self):
        return self[1]

    def pair(self):
        return self

    def curve(self):
        return self._curve
