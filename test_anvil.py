"""Basic test suite for ANVIL - validates core module imports."""

def test_anvil_imports():
    """Test that the ANVIL module can be imported."""
    import ANVIL  # noqa: F401
    assert ANVIL is not None


def test_basic_initialization():
    """Test basic ANVIL initialization."""
    from ANVIL import GsaKernel
    assert GsaKernel is not None
