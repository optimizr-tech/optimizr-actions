from pathlib import Path
import tempfile
import unittest

from scripts.delivery.lock import DeliveryLockError, service_lock


class DeliveryLockTests(unittest.TestCase):
    def test_lock_file_is_scoped_to_the_service_and_can_be_reacquired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            with service_lock(root, "optimizr-serve"):
                lock_path = root / "optimizr-serve.lock"
                self.assertTrue(lock_path.is_file())
                self.assertFalse((root / "other-service.lock").exists())

            with service_lock(root, "optimizr-serve"):
                self.assertTrue(lock_path.is_file())

    def test_rejects_unsafe_service_and_lock_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            with self.assertRaisesRegex(DeliveryLockError, "service"):
                with service_lock(root, "../serve"):
                    pass

            with self.assertRaisesRegex(DeliveryLockError, "root"):
                with service_lock(root / "missing", "serve"):
                    pass


if __name__ == "__main__":
    unittest.main()
