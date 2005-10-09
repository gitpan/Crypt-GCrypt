# ===========================================================================
# Crypt::GCrypt - version 1.00 - 09 Oct 2005
# 
# Perl interface to the GNU Cryptographic library
# 
# Author: Alessandro Ranellucci <aar@cpan.org>
# Copyright (c) 2005 - All Rights Reserved.
# 
# Use this software AT YOUR OWN RISK.
# See below for documentation.
# 

package Crypt::GCrypt;

use strict;
use warnings;

our $VERSION = '1.00';

require XSLoader;
XSLoader::load('Crypt::GCrypt', $VERSION);

1;
__END__

=head1 NAME

Crypt::GCrypt - Perl interface to the GNU Cryptographic library

=head1 SYNOPSIS

  use Crypt::GCrypt;
  
  $cipher = GCrypt::Cipher->new(
    type => 'cipher',
    algorithm => 'aes', 
    mode => 'cbc'
  );
  
  $cipher->setkey('my secret key');
  
  $cipher->setiv('my init vector');
  
  $ciphertext = $cipher->encrypt('plaintext');
  
  $plaintext  = $cipher->decrypt($ciphertext);

=head1 ABSTRACT

Crypt::GCrypt provides an object interface to the C libgcrypt library. It
currently supports symmetric encryption, while asymmetric encryption is 
being worked on.

=head1 SYMMETRIC CRYPTOGRAPHY

In order to encrypt/decrypt your data using a symmetric cipher you first have
to build a Crypt::GCrypt object:

  $cipher = GCrypt::Cipher->new(
    type => 'cipher',
    algorithm => 'aes', 
    mode => 'cbc'
  );
  
The I<type> argument must be "cipher" and the I<algorithm> is required. See below
for a description of available algorithms and other initialization parameters:

=over 4

=item algorithm

This may be one of the following:

=over 8

=item B<3des> 

(Triple DES, 112 bit key)

=item B<aes> 

(The Advanced Encryption Standard, a.k.a. Rijndael, 128 bit key)

=item B<aes192> 

(AES with 192 bit key)

=item B<aes256> 

(AES with 256 bit key)

=item B<blowfish>

=item B<cast5>

=item B<des> 

(Date Encryption Standard, 56 bit key, not very secure as it's too short)

=item B<twofish> 

(Successor of Blowfish, 256 bit key)

=item B<arcfour> 

(Stream cipher)

=back

=item mode

This is a string specifying one of the following
encryption/decryption modes:

=over 8

=item B<stream> 

only available for stream ciphers

=item B<ecb> 

doesn't use an IV, encrypts each block independently

=item B<cbc> 

the current ciphertext block is encryption of current plaintext block xor-ed with last ciphertext block

=item B<cfb> 

the current ciphertext block is the current plaintext
block xor-ed with the current keystream block, which is the encryption
of the last ciphertext block

=item B<ofb> 

the current ciphertext block is the current plaintext
block xor-ed with the current keystream block, which is the encryption
of the last keystream block

=back

If no mode is specified B<cbc> is selected for block ciphers, and
B<stream> for stream ciphers. Between blocks the previous one is stored in the IV.


=item secure


All data associated with this cipher will be put into non-swappable storage, 
if possible.

=item enable_sync

Enable the CFB sync operation.

=back

Once you've got your cipher object the following methods are available:

=over 4

=item $cipher->setkey(I<KEY>)

Encryption and decryption operations will use I<KEY> until a different
one is set. If I<KEY> is shorter than the cipher's keylen (see the
C<keylen> method) it will be zero-padded, if it is longer it will be
truncated.

=item $cipher->setiv([I<IV>])

Set the initialisation vector to I<IV> for the next encrypt/decrypt operation.
If I<IV> is missing a "standard" IV of all zero is used. The same IV is set in
newly created cipher objects.

=item $cipher->encrypt(I<PLAINTEXT>)

This method encrypts I<PLAINTEXT> with $cipher, returning the
corresponding ciphertext. Null byte padding is automatically appended
if I<PLAINTEXT>'s length is not evenly divisible by $cipher's block
size.

=item $cipher->decrypt(I<CIPHERTEXT>)

The counterpart to encrypt, decrypt takes a I<CIPHERTEXT> and produces the
original plaintext (given that the right key was used, of course).

=item $cipher->keylen()

Returns the number of bytes of keying material this cipher needs.

=item $cipher->blklen()

As their name implies, block ciphers operate on blocks of data. This
method returns the size of this blocks in bytes for this particular
cipher. For stream ciphers C<1> is returned, since this implementation
does not support feeding less than a byte into the cipher.

=item $cipher->sync()

Apply the CFB sync operation.

=head1 AVAILABILITY

Latest versions can be downloaded from CPAN. You are very welcome to write mail 
to the author (aar@cpan.org) with your contributions, comments, suggestions, 
bug reports or complaints.

=head1 AUTHOR

Alessandro Ranellucci E<lt>aar@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2005 Alessandro Ranellucci.
Crypt::GCrypt is free software, you may redistribute it and/or modify it under 
the same terms as Perl itself.

=head1 ACKNOWLEDGEMENTS

This module is partially inspired by the GCrypt.pm bindings made by 
Robert Bihlmeyer in 2002.

=head1 DISCLAIMER

This software is provided by the copyright holders and contributors ``as
is'' and any express or implied warranties, including, but not limited to,
the implied warranties of merchantability and fitness for a particular
purpose are disclaimed. In no event shall the regents or contributors be
liable for any direct, indirect, incidental, special, exemplary, or
consequential damages (including, but not limited to, procurement of
substitute goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether in
contract, strict liability, or tort (including negligence or otherwise)
arising in any way out of the use of this software, even if advised of the
possibility of such damage.

=cut
