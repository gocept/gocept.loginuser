import gocept.loginuser.password
import gocept.testing.patch
import hashlib
import pytest
import six


@pytest.yield_fixture(scope='module', autouse=True)
def patches():
    """Patch bcrypt WORK_FACTOR to speed up tests."""
    patch = gocept.testing.patch.Patches()
    patch.set(gocept.loginuser.password, 'WORK_FACTOR', 4)
    yield
    patch.reset()


def test_password__check__1():
    """`check()` verifies a password."""
    hashed = gocept.loginuser.password.hash('mypassword')
    assert gocept.loginuser.password.check('mypassword', hashed)
    assert not gocept.loginuser.password.check('invalid', hashed)


def test_password__check__2():
    """`check()` defaults to bcrypt."""
    hashed = gocept.loginuser.password.hash(u'asdf')
    assert gocept.loginuser.password.check('asdf', hashed)


def test_password__check__3():
    """`check()` recognizes sha256:<hash>."""
    hashed = hashlib.sha256(b'asdf').hexdigest()
    assert gocept.loginuser.password.check('asdf', 'sha256:' + hashed)


def test_password__hash__1():
    """`hash()` accepts and returns unicode."""
    hashed = gocept.loginuser.password.hash(u'mypassword')
    assert isinstance(hashed, six.text_type)
