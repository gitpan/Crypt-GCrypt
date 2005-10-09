use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'		=> 'Crypt::GCrypt',
    'ABSTRACT'	=> 'Perl interface to the GNU libgcrypt library',
    'AUTHOR'	=> 'Alessandro Ranellucci <aar@cpan.org>',
    'VERSION_FROM'	=> 'GCrypt.pm',
    'LIBS'		=> ['-lgcrypt'],
    'DEFINE'		=> '',
    'INC'		=> '-I.',
    'dist'         	=> { COMPRESS => 'gzip', SUFFIX => 'gz' }
);
