
class NoSuchPointError(ValueError):
    pass


class Point(tuple):
    """
    A point on an elliptic curve. This is a subclass of tuple (forced to a 2-tuple),
    and also includes a reference to the underlying Curve.

    This class supports the operators ``+``, ``-`` (unary and binary) and ``*``.

    :param x: x coordinate
    :param y: y coordinate
    :param curve: the :class:`Curve <pycoin.ecdsa.Curve.Curve>` this point must be on

    The constructor raises :class:`NoSuchPointError` if the point is invalid.
    The point at infinity is ``(x, y) == (None, None)``.
    """
    def __new__(self, x, y, curve):
        """
        Subclasses of tuple require __new__ to be overridden.
        """
        return tuple.__new__(self, (x, y))

    def __init__(self, x, y, curve):
        self._curve = curve
        super(Point, self).__init__()
        self.check_on_curve()

    def check_on_curve(self):
        """raise :class:`NoSuchPointError` if the point is not actually on the curve."""
        if not self._curve.contains_point(*self):
            raise NoSuchPointError('({},{}) is not on the curve {}'.format(self[0], self[1], self._curve))

    def __add__(self, other):
        """Add one point to another point."""
        return self._curve.add(self, other)

    def __sub__(self, other):
        """Subtract one point from another point."""
        return self._curve.add(self, -other)

    def __mul__(self, e):
        """Multiply a point by an integer."""
        return self._curve.multiply(self, e)

    def __rmul__(self, other):
        """Multiply a point by an integer."""
        return self * other

    def __neg__(self):
        """Unary negation"""
        return self.__class__(self[0], self._curve.p()-self[1], self._curve)

    def curve(self):
        """:return: the :class:`Curve <pycoin.ecdsa.Curve>` this point is on"""
        return self._curve
