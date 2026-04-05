from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .Curve import Curve


class NoSuchPointError(ValueError):
    pass


class Point(tuple[int | None, int | None]):
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

    def __new__(cls, x: int | None, y: int | None, curve: Curve) -> Point:
        """
        Subclasses of tuple require __new__ to be overridden.
        """
        return tuple.__new__(cls, (x, y))

    def __init__(self, x: int | None, y: int | None, curve: Curve) -> None:
        self._curve = curve
        super(Point, self).__init__()
        self.check_on_curve()

    def check_on_curve(self) -> None:
        """raise :class:`NoSuchPointError` if the point is not actually on the curve."""
        if not self._curve.contains_point(*self):
            raise NoSuchPointError(
                "({},{}) is not on the curve {}".format(self[0], self[1], self._curve)
            )

    def __add__(self, other: Point) -> Point:  # type: ignore[override]
        """Add one point to another point."""
        return self._curve.add(self, other)

    def __sub__(self, other: Point) -> Point:
        """Subtract one point from another point."""
        return self._curve.add(self, -other)

    def __mul__(self, e: int) -> Point:  # type: ignore[override]
        """Multiply a point by an integer."""
        return self._curve.multiply(self, e)

    def __rmul__(self, other: int) -> Point:  # type: ignore[override]
        """Multiply a point by an integer."""
        return self * other

    def __neg__(self) -> Point:
        """Unary negation"""
        return self.__class__(self[0], self._curve.p() - self[1], self._curve)  # type: ignore[operator]

    def curve(self) -> Curve:
        """:return: the :class:`Curve <pycoin.ecdsa.Curve>` this point is on"""
        return self._curve
