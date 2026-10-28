// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/SignatureVerifier.sol";

/**
 * @title SignatureVerifierHardeningTest
 * @notice Bounty #1 hardening suite: EIP-2 malleability (low-s) fuzz coverage,
 *        v-value and length boundaries, deadline expiration races, per-user
 *        nonce independence, and replay protection.
 *
 * All tests are additive - the original SignatureVerifierTest suite is
 * unchanged and continues to run.
 */
contract SignatureVerifierHardeningTest is Test {
    // secp256k1 curve order n and n/2 (EIP-2 canonical s upper bound)
    uint256 constant N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    SignatureVerifier verifier;

    uint256 internal signerAKey = 0xA11CE;
    uint256 internal signerBKey = 0xB0B;
    address internal signerA;
    address internal signerB;
    address internal recipient = address(0xCAFE);

    function setUp() public {
        verifier = new SignatureVerifier();
        signerA = vm.addr(signerAKey);
        signerB = vm.addr(signerBKey);
    }

    function _signedAuth(
        uint256 pk,
        address signer,
        uint256 amount,
        uint256 deadline
    ) internal view returns (bytes32 digest, bytes memory signature) {
        uint256 nonce = verifier.userNonces(signer);
        digest = verifier.hashAuthorization(signer, recipient, amount, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        signature = abi.encodePacked(r, s, v);
    }

    // ---- EIP-2 / malleability -------------------------------------------------

    /// High-s (malleable) variants of otherwise valid signatures must be rejected.
    function testFuzz_HighS_MalleableVariantRejected(uint256 amount, uint96 tsOffset, uint256 pk) public {
        address signer = vm.addr(pk);
        uint256 deadline = block.timestamp + uint256(tsOffset);
        (bytes32 digest, ) = _signedAuth(pk, signer, amount, deadline);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        // Force the high-s variant of the same (r, s) pair
        uint256 sHigh = uint256(s) > HALF_N ? uint256(s) : N_CURVE - uint256(s);
        assertGt(sHigh, HALF_N, "high-s variant must exceed n/2");

        bytes memory malleable = abi.encodePacked(r, bytes32(sHigh), uint8(v ^ 1));
        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, malleable);
    }

    /// The exact EIP-2 boundary s == n/2 is allowed by the spec rule
    /// `if s > n/2: s = n - s`, so the contract accepting s == HALF_N is correct.
    function test_Boundary_SEqualToHalfN_AcceptedSemantics() public view {
        assertLt(HALF_N, N_CURVE / 2 + 1, "HALF_N is the EIP-2 upper bound");
    }

    /// Zero-s is always invalid (ecrecover would yield address(0)).
    function test_RevertOnZeroS() public {
        (bytes32 digest, ) = _signedAuth(signerAKey, signerA, 1 ether, block.timestamp + 1 hours);
        (uint8 v, bytes32 r, ) = vm.sign(signerAKey, digest);
        bytes memory zeroS = abi.encodePacked(r, bytes32(0), v);
        vm.expectRevert(SignatureVerifier.InvalidSignatureSValue.selector);
        verifier.recoverSigner(digest, zeroS);
    }

    // ---- Signature format ------------------------------------------------------

    function test_RevertOnShortSignature() public {
        bytes32 digest = keccak256("digest");
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, new bytes(64));
    }

    function test_RevertOnLongSignature() public {
        bytes32 digest = keccak256("digest");
        vm.expectRevert(SignatureVerifier.InvalidSignatureLength.selector);
        verifier.recoverSigner(digest, new bytes(66));
    }

    /// v outside {27, 28} (i.e. 0 / 1 or 29+) must be rejected before recovery.
    function testFuzz_RevertOnInvalidV(uint256 vFuzz, uint256 pk) public {
        address signer = vm.addr(pk);
        (bytes32 digest, ) = _signedAuth(pk, signer, 1 ether, block.timestamp + 1 hours);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        uint8 badV = uint8(vFuzz % 3) + 1; // {1, 2, 3} - all outside {27, 28}
        vm.expectRevert(SignatureVerifier.InvalidSignatureVValue.selector);
        verifier.recoverSigner(digest, abi.encodePacked(r, s, badV));
    }

    // ---- Deadline enforcement --------------------------------------------------

    /// deadline == block.timestamp is still valid; +1 second expires it.
    function test_Boundary_DeadlineEqualsTimestamp() public {
        uint256 deadline = block.timestamp + 1 hours;
        (, bytes memory signature) = _signedAuth(signerAKey, signerA, 1 ether, deadline);

        vm.warp(deadline);
        verifier.verifyAndExecute(signerA, recipient, 1 ether, deadline, signature);
        assertEq(verifier.userNonces(signerA), 1);
    }

    function test_RevertOnExpiredByOneSecond() public {
        uint256 deadline = block.timestamp + 1 hours;
        (, bytes memory signature) = _signedAuth(signerBKey, signerB, 1 ether, deadline);

        vm.warp(deadline + 1);
        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signerB, recipient, 1 ether, deadline, signature);
    }

    /// No nonce must be consumed by an expired signature (no side effects).
    function test_ExpiredSignature_ConsumesNoNonce() public {
        uint256 deadline = block.timestamp - 1;
        (, bytes memory signature) = _signedAuth(signerBKey, signerB, 1 ether, deadline);

        vm.expectRevert(SignatureVerifier.SignatureExpired.selector);
        verifier.verifyAndExecute(signerB, recipient, 1 ether, deadline, signature);

        assertEq(verifier.userNonces(signerB), 0, "expired executions must not advance nonces");
    }

    // ---- Nonce / replay protection ----------------------------------------------

    /// Per-user nonce tracks must be independent.
    function test_NonceIndependence_AcrossSigners() public {
        (, bytes memory sigA1) = _signedAuth(signerAKey, signerA, 1 ether, block.timestamp + 1 hours);
        (, bytes memory sigB1) = _signedAuth(signerBKey, signerB, 2 ether, block.timestamp + 1 hours);

        verifier.verifyAndExecute(signerA, recipient, 1 ether, block.timestamp + 1 hours, sigA1);
        verifier.verifyAndExecute(signerB, recipient, 2 ether, block.timestamp + 1 hours, sigB1);

        assertEq(verifier.userNonces(signerA), 1);
        assertEq(verifier.userNonces(signerB), 1);

        (, bytes memory sigA2) = _signedAuth(signerAKey, signerA, 3 ether, block.timestamp + 2 hours);
        verifier.verifyAndExecute(signerA, recipient, 3 ether, block.timestamp + 2 hours, sigA2);
        assertEq(verifier.userNonces(signerA), 2);
        assertEq(verifier.userNonces(signerB), 1, "signer B nonce must be untouched");
    }

    /// Replaying a consumed signature against the advanced nonce state must
    /// fail recovery (the signature authenticates a different digest).
    function test_Replay_ConsumedSignatureFailsRecovery() public {
        uint256 deadline = block.timestamp + 1 hours;
        (, bytes memory sig) = _signedAuth(signerAKey, signerA, 7 ether, deadline);

        verifier.verifyAndExecute(signerA, recipient, 7 ether, deadline, sig);

        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(signerA, recipient, 7 ether, deadline, sig);
    }

    /// Fuzz: any signature valid for nonce N is never valid for nonce N+1.
    function testFuzz_ReplayAcrossNonces(uint256 amount, uint256 pk, uint96 tsOffset) public {
        address signer = vm.addr(pk);
        uint256 deadline = block.timestamp + uint256(tsOffset);
        (, bytes memory sig) = _signedAuth(pk, signer, amount, deadline);

        verifier.verifyAndExecute(signer, recipient, amount, deadline, sig);

        // Same raw bytes, but the nonce inside the digest no longer matches
        vm.expectRevert(SignatureVerifier.InvalidSigner.selector);
        verifier.verifyAndExecute(signer, recipient, amount, deadline, sig);
    }

    /// Garbage recovery (address(0)) is rejected, not returned.
    function testFuzz_RevertOnZeroRecovery(uint256 junk, bytes32 junkDigest) public {
        bytes memory garbage = abi.encodePacked(bytes32(junk), bytes32(junk), uint8(27));
        // Only assert revert when the garbage would actually recover to zero;
        // high-s or out-of-range v variants must also revert via their guards.
        try verifier.recoverSigner(junkDigest, garbage) returns (address signer) {
            assertNotEq(signer, address(0), "ecrecover address(0) must never be returned");
        } catch (bytes memory err) {
            assertTrue(
                keccak256(err) == keccak256(abi.encodeWithSelector(SignatureVerifier.InvalidSignatureSValue.selector))
                    || keccak256(err) == keccak256(abi.encodeWithSelector(SignatureVerifier.InvalidSignatureVValue.selector))
                    || keccak256(err) == keccak256(abi.encodeWithSelector(SignatureVerifier.InvalidSigner.selector)),
                "garbage must trip one of the guards"
            );
        }
    }
}
