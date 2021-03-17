#include "ssh.h"

bool have_ssh_host_key( Ssh *ssh, const char *algorithm )
{
	bool ret = false;

	if ( ssh != NULL )
	{
		for ( unsigned int i = 0; i < ssh->key_info_count; ++i )
		{
			if ( strcmp( algorithm, ssh->key_info[ i ].algorithm ) == 0 )
			{
				return true;
			}
		}
	}

	return ret;
}
