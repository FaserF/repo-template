import pytest
from src.sample_calculator import divide_numbers

def test_divide_numbers():
    assert divide_numbers(10.0, 2.0) == 5.0

def test_divide_by_zero():
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide_numbers(10.0, 0.0)
