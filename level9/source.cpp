#include <unistd.h>
#include <cstring>

class N
{
    public:
        int nb;
        char annotation[100];
        int (N::*func)(N&);

        N(int nb)
        {
            this->nb = nb;
            this->func = operator+;
        }


        int operator+(N &right)
        {
            return this->nb + right.nb;
        }

        int operator-(N &right)
        {
            return this->nb - right.nb;
        }

        void setAnnotation(char *str)
        {
            memcpy(this->annotation, str, strlen(str));
        }
};

int		main(int ac, char **av)
{
	if (ac < 1)
		_exit(1);
	N *objA = new N(5);
	N *objB = new N(6);
	objA->setAnnotation(av[1]);
	return (objB->*(objB->func))(*objA);
}