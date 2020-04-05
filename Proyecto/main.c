#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
#include <stdint.h>
#include <inttypes.h>

/** tipos de consultas manejados */
#define T_A 1
#define T_MX 15
#define T_LOC 29    /** RFC 1876: LOCation information, geographical location, experimental RFC **/
#define T_SOA 6
#define T_NS 2

/** Variables globales **/
char dns_servers[10][100]; // Listado de servidores dns dentro del sistema
char *servidorDNS; // Por defecto: se le asignará dns_servers[0]
char *puerto = "53"; // Por defecto: 53
char *tipoConsulta = "-a";
char *maneraConsulta = "-r";

/** tipos de datos definidos */
/** Formato de mensaje DNS **/
/**
El formato de mensaje de nivel superior se divide en 5 secciones:
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | la pregunta para el servidor de nombres
    +---------------------+
    |        Answer       | RRs respondiendo la pregunta
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
**/

/** Formato de la sección Header **/
/** El header contiene los siguientes campos:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
**/
typedef struct HEADER
{
    /** Un identificador de 16 bits **/
    unsigned short id;
    /** Recursion desired **/
    unsigned char rd :1;
    /** TrunCation: especifica si el mensaje fue truncado **/
    unsigned char tc :1;
    /** Authoritive answer **/
    unsigned char aa :1;
    /** Opcode:
    Un campo de 4 bits que especifica el tipo de consulta en el mensaje . Los valores son:
        0      standard query (QUERY)
        1      inverse query (IQUERY)
        2      server status request (STATUS)
        3-15   reservado para un uso futuro
    **/
    unsigned char opcode :4;
    /** Un campo de un bir que especifica si es una consulta (0) o una respuesta (1) **/
    unsigned char qr :1;
    /** Campo de 4 bits, código de respuesta **/
    unsigned char rcode :4;
    /** Z: Reservado para un uso futuro.
        Debe ser 0 en todas las consultas y respuestas.
    **/
    unsigned char z :1;
    /** Recursion Available **/
    unsigned char ra :1;
    /** QDCOUNT:
    Un entero de 16 bits sin signo que especifica el número de entradas en la sección Question.
    **/
    unsigned short qdcount;
    /**
    Un entero de 16 bits sin signo que especifica el número de resource records en la sección Answer.
    **/
    unsigned short ancount;
    /**
    Un entero de 16 bits sin signo que especifica el número de resource records del servidor de
    nombres en la sección Authority.
    **/
    unsigned short nscount;
    /**
    Un entero de 16 bits sin signo que especifica el número de resource records del servidor de
    nombres en la sección Additional.
    **/
    unsigned short arcount;
} seccion_header;

/** Formato de la sección Question **/
/**
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
**/
typedef struct QUESTION
{
    /** QNAME forma parte de esta sección también, un nombre de dominio codificado en labels **/
    /** Un código de dos octetos que especifica el tipo de la consulta **/
    unsigned short qtype;
    /** Un código de dos octetos que especifica la clase de la consulta
        Por ejemplo, el campo QCLASS es IN para Internet **/
    unsigned short qclass;
} seccion_question;

/** 4.1.3. Formato de los Resource record (RR) **/
/**
Las secciones Answer, Authority y Additional comparten el mismo
formato: un número variable de resource records, donde el número de
registros (records) se especifican en el campo count correspondiente en el Header.
Cada RR tiene el siguiente formato:
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
**/
/**
NAME            a domain name to which this resource record pertains.

TYPE            two octets containing one of the RR type codes.  This
                field specifies the meaning of the data in the RDATA
                field.

CLASS           two octets which specify the class of the data in the
                RDATA field.

TTL             a 32 bit unsigned integer that specifies the time
                interval (in seconds) that the resource record may be
                cached before it should be discarded.  Zero values are
                interpreted to mean that the RR can only be used for the
                transaction in progress, and should not be cached.

RDLENGTH        an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.

RDATA           a variable length string of octets that describes the
                resource.  The format of this information varies
                according to the TYPE and CLASS of the resource record.
                For example, the if the TYPE is A and the CLASS is IN,
                the RDATA field is a 4 octet ARPA Internet address.
**/

//Constant sized fields of the resource record structure
//short es de 16bits, int es de 32 bits
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short rdlength;
};

//Pointers to resource record contents
struct RESOURCE_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    seccion_question *ques;
} QUERY;

/**
      LOC RDATA Format

       MSB                                           LSB
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      0|        VERSION        |         SIZE          |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      2|       HORIZ PRE       |       VERT PRE        |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      4|                   LATITUDE                    |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      6|                   LATITUDE                    |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      8|                   LONGITUDE                   |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     10|                   LONGITUDE                   |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     12|                   ALTITUDE                    |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     14|                   ALTITUDE                    |
       +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   (octet)

where:

VERSION      Version number of the representation.  This must be zero.
             Implementations are required to check this field and make
             no assumptions about the format of unrecognized versions.

SIZE         The diameter of a sphere enclosing the described entity, in
             centimeters, expressed as a pair of four-bit unsigned
             integers, each ranging from zero to nine, with the most
             significant four bits representing the base and the second
             number representing the power of ten by which to multiply
             the base.  This allows sizes from 0e0 (<1cm) to 9e9
             (90,000km) to be expressed.  This representation was chosen
             such that the hexadecimal representation can be read by
             eye; 0x15 = 1e5.  Four-bit values greater than 9 are
             undefined, as are values with a base of zero and a non-zero
             exponent.

             Since 20000000m (represented by the value 0x29) is greater
             than the equatorial diameter of the WGS 84 ellipsoid
             (12756274m), it is therefore suitable for use as a
             "worldwide" size.

HORIZ PRE    The horizontal precision of the data, in centimeters,
             expressed using the same representation as SIZE.  This is
             the diameter of the horizontal "circle of error", rather
             than a "plus or minus" value.  (This was chosen to match
             the interpretation of SIZE; to get a "plus or minus" value,
             divide by 2.)

VERT PRE     The vertical precision of the data, in centimeters,
             expressed using the sane representation as for SIZE.  This
             is the total potential vertical error, rather than a "plus
             or minus" value.  (This was chosen to match the
             interpretation of SIZE; to get a "plus or minus" value,
             divide by 2.)  Note that if altitude above or below sea
             level is used as an approximation for altitude relative to
             the [WGS 84] ellipsoid, the precision value should be
             adjusted.

LATITUDE     The latitude of the center of the sphere described by the
             SIZE field, expressed as a 32-bit integer, most significant
             octet first (network standard byte order), in thousandths
             of a second of arc.  2^31 represents the equator; numbers
             above that are north latitude.

LONGITUDE    The longitude of the center of the sphere described by the
             SIZE field, expressed as a 32-bit integer, most significant
             octet first (network standard byte order), in thousandths
             of a second of arc, rounded away from the prime meridian.
             2^31 represents the prime meridian; numbers above that are
             east longitude.

ALTITUDE     The altitude of the center of the sphere described by the
             SIZE field, expressed as a 32-bit integer, most significant
             octet first (network standard byte order), in centimeters,
             from a base of 100,000m below the [WGS 84] reference
             spheroid used by GPS (semimajor axis a=6378137.0,
             reciprocal flattening rf=298.257223563).  Altitude above
             (or below) sea level may be used as an approximation of
             altitude relative to the the [WGS 84] spheroid, though due
             to the Earth's surface not being a perfect spheroid, there
             will be differences.  (For example, the geoid (which sea
             level approximates) for the continental US ranges from 10
             meters to 50 meters below the [WGS 84] spheroid.
             Adjustments to ALTITUDE and/or VERT PRE will be necessary
             in most cases.  The Defense Mapping Agency publishes geoid
             height values relative to the [WGS 84] ellipsoid.
*/

struct R_DATA_LOC
{
    unsigned char version;
    unsigned char size;
    unsigned char horiz_pre;
    unsigned char vert_pre;
    uint32_t latitude;
    uint32_t longitude;
    uint32_t altitude;
};

/**
    SOA RDATA format
                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     MNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     RNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    SERIAL                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    REFRESH                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RETRY                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    EXPIRE                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    MINIMUM                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

MNAME           The <domain-name> of the name server that was the
                original or primary source of data for this zone.

RNAME           A <domain-name> which specifies the mailbox of the
                person responsible for this zone.

SERIAL          The unsigned 32 bit version number of the original copy
                of the zone.  Zone transfers preserve this value.  This
                value wraps and should be compared using sequence space
                arithmetic.

REFRESH         A 32 bit time interval before the zone should be
                refreshed.

RETRY           A 32 bit time interval that should elapse before a
                failed refresh should be retried.

EXPIRE          A 32 bit time value that specifies the upper limit on
                the time interval that can elapse before the zone is no
                longer authoritative.

MINIMUM         The unsigned 32 bit minimum TTL field that should be
                exported with any RR from this zone.

SOA records cause no additional section processing.

    */

struct R_DATA_SOA
{
    uint32_t name;
    uint16_t rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
};

/** ¿Cómo se representa un nombre de dominio dentro del paquete DNS? **/
/** El nombre de dominio se representa en forma de labels separadas por puntos (.):
    {label}.{label}.{label}
    Un label puede ser de tipo data label
    Un data label está compuesto por:
    - Longitud del elabel: un byte que describe la longitud de la label actual (justo antes del punto).
      El valor oscila entre 0 y 63.
    - Los bytes del label actual. Su tamaño máximo es de 63 bytes.
    Ejemplo:
    El nombre de dominio "www.facebook.com" tiene tres labels y está codificado en el mensaje DNS en este formato:
    3 'w' 'w' 'w' 8 'f' 'a' 'c' 'e' 'b' 'o' 'o' 'k' 3 'c' 'o' 'm' 0
    El último 0 es por el label raíz. Recordar que todos los nombres de dominio DNS terminan con un dominio raíz; el punto.
**/
void cambiarAlFormatoNombreDNS(unsigned char* dns, char* host)
{
    //A modo de síntesis, recorro la cadena contando en "lock" cuantos caracteres insumo, una vez llegado el punto
    //inserto en su lugar i-lock, es decir, el lugar actual menos lo que contiene lock (inicialmente lock es 0 por lo
    //que se inserta el índice actual), quedando asi la cantidad de caracteres que contiene esa sección del nombre
    //por otro lado, se escriben en la salida (dns) se guardan los caracteres hasta el proximo punto, incrementando
    //el valor del lock. El valor de i se incrementa en el for exterior.
    if (host[0] == '.' && strlen((char*)host) == 1)   /** Raiz **/
    {
        *dns++='\0';
    }
    else
    {
        int lock = 0 , i;
        strcat((char*)host,".");
        for(i = 0 ; i < strlen((char*)host) ; i++)
        {
            if(host[i]=='.')
            {
                *dns++ = i-lock;    //guardo i-lock y luego incremento dicho valor en 1.
                for(; lock<i; lock++)
                {
                    *dns++=host[lock];
                }
                lock++;
            }
        }
        *dns++='\0';
        host[strlen((char*)host)-1]='\0';//quito el punto que agregue mas arriba.
    }
}

/** Del formato DNS al formato "humano" con '.'
    inicialmente lee un nombre en formato dns y luego en una segunda parte lo convierte al formato con puntos
**/
u_char* leerNombre(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0]='\0';

    //lee los nombres en format 3www6google3com0
    while(*reader!=0)
    {
        //conversion del caracter.
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //*reader = caracter actual apuntado, *(reader+1) = caracter siguiente, 49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else
        {
            name[p++]=*reader;  //leo un caracter y luego incremento en 1 el puntero p
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1;
        }
    }

    name[p]='\0'; //string completo
    if(jumped==1)
    {
        *count = *count + 1;
    }

    //se convierte 3www6google3com0 a www.google.com
    for(i=0; i<(int)strlen((const char*)name); i++)
    {
        p=name[i];
        for(j=0; j<(int)p; j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; // remueve el último punto
    return name;
}

/** mapearTipo: Simplemente mapea los tipos manejados por el programa a un texto imprimible **/
char* mapearTipo(int tipo){
    switch(tipo){
        case T_A:
            return "A";
        case T_MX:
            return "MX";
        case T_LOC:
            return "LOC";
        case T_SOA:
            return "SOA";
        case T_NS:
            return "NS";
    }
    return "error";
}

/** C substring function: It returns a pointer to the substring */
char *cortarString(char *string, int position, int length)
{
    char *pointer;
    int c;

    pointer = malloc(length+1);

    if (pointer == NULL)
    {
        printf("Unable to allocate memory.\n");
        exit(1);
    }

    for (c = 0 ; c < length ; c++)
    {
        *(pointer+c) = *(string+position-1);
        string++;
    }

    *(pointer+c) = '\0';

    return pointer;
}

/** Muestra la ayuda por pantalla */
void mostrarAyuda()
{
    printf("AYUDA:\nUso: query consulta @servidor[:puerto] [-a | -mx | -loc] [-r | -t] [-h]\n");
    printf("consulta: la consulta que se desea resolver (en general, la cadena de\n"\
           "caracteres denotando el nombre simbólico que se desea mapear a un IP)\n");
    printf("@servidor: el cliente debe resolver la consulta suminstrada contra el servidor\n"\
           "DNS que se especifique con este argumento. Caso contrario, se resolverá la\n"\
           "consulta suministrada contra el servidor DNS por defecto\n");
    printf("[:puerto]: parámetro opcional si se especificó un servidor. Permite indicar\n"\
           "que el servidor contral el cual se resolverá la consulta no está ligado\n"\
           "al puerto DNS estándar. Caso contrario, se asume que las consultas serán\n"\
           "dirigidas al puerto estándar del servidor\n");
    printf("[-a | -mx | -loc]: parámetros opcionales excluyentes entre sí. Denotan el\n"\
           "tipo de consulta que se está realizando.\n");
    printf("\t-a: la consulta se trata de un nombre simbólico y se desea conocer su\n"\
           "\tcorrespondiente IP número asociado\n");
    printf("\t-mx: se desea determinar el servidor a cargo de la recepción de correo\n"\
           "\telectrónico para el dominio indicado en la consulta\n");
    printf("\t-loc: se desea recuperar la información relativa a la ubicación\n"\
           "\tgeográfica del dominio indicado en la consulta\n");
    printf("\tEn caso de no indicarse el tipo de consulta, se asume -a\n");
    printf("[-r | -t]: parámetros opcionales excluyentes entre sí. Denotan la manera\n"\
           "en la cual se desea resolver la consulta.\n");
    printf("\t-r: se está solicitando que la consulta contenga el bit recursion\n"\
           "\tdesired activado\n");
    printf("\t-t: se está solicitando que la consulta se resuelva iterativamente,\n"\
           "\tmostrando una traza con la evolución de la misma\n");
    printf("\tEn caso de no indicarse la manera de consulta, se asume que la consulta\n"\
           "\tdebe ser resuelta de manera recursiva\n");
    printf("-h: parámetro opcional, modo ayuda\n");
}

/** obtengo los servidores dns locales, directo desde el archivo /etc/resolv.conf **/
void get_dns_servers()
{
    FILE *fp;
    char line[200] , *p;
    if((fp = fopen("/etc/resolv.conf" , "r")) == NULL)
    {
        printf("Falló abriendo el archivo /etc/resolv.conf\n");
    }
    int i = 0;
    while(fgets(line , 200 , fp))
    {
        if(line[0] == '#')
        {
            continue;
        }
        if(strncmp(line , "nameserver" , 10) == 0)
        {
            char toks[] = " \n"; // espacios y saltos de línea
            p = strtok(line, toks);
            p = strtok(NULL , toks);
            strcat(dns_servers[i],p);
            i++;
        }
    }
}

unsigned int littleToBigEndian(unsigned int x)
{
    return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}

/** modificado del código de RFC 1876 **/
int precsize_ntoa(uint8_t prec)
{
    unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
                                   1000000,10000000,100000000,1000000000
                                  };
    unsigned long val;
    int mantissa, exponent;

    mantissa = (int)((prec >> 4) & 0x0f) % 10;
    exponent = (int)((prec >> 0) & 0x0f) % 10;
    val = mantissa * poweroften[exponent];
    val = val / 100;

    return val;
}



/** Imprime resultados de una consulta **/
void printResults(struct RESOURCE_RECORD answer[],struct RESOURCE_RECORD authority[],struct RESOURCE_RECORD additional[],struct R_DATA_LOC* answerLOC,
                  int respuestasA,int respuestasAU,int respuestasADD,char* host,int query_type)
{
    struct sockaddr_in a; // variable utilizada para obtener la direccion IP en un RDATA de tipo A (IPv4)
    if(strcmp(maneraConsulta,"-r")==0){
        if (query_type==T_A)
            printf("\n; QUERY: %d, ANSWER: %d, AUTORITHY: %d, ADDITIONAL: %d\n",1,respuestasA,respuestasAU,respuestasADD);
        if (query_type==T_MX)
            printf("\n; QUERY: %d, ANSWER: %d, AUTORITHY: %d, ADDITIONAL: %d\n",1,respuestasA,respuestasAU,respuestasADD);
        if (query_type==T_LOC)
            printf("\n; QUERY: %d, ANSWER: %d, AUTORITHY: %d, ADDITIONAL: %d\n",1,respuestasA,respuestasAU,respuestasADD);
        if (query_type==T_NS)
            printf("\n; QUERY: %d, ANSWER: %d, AUTORITHY: %d, ADDITIONAL: %d\n",1,respuestasA,respuestasAU,respuestasADD);

        printf("\n;; QUESTION SECTION:\n" );
        if(query_type == T_A)
            printf(";%s\tIN\tA\n",host);
        if(query_type == T_MX)
            printf(";%s\tIN\tMX\n",host);
        if(query_type == T_LOC)
            printf(";%s\tIN\tLOC\n",host);
        if(query_type == T_NS)
            printf(";%s\tIN\tNS\n",host);
    }

    int i=0;

    /** imprime los RR authorities **/
    if (respuestasA > 0)
    {
        printf("\n;; ANSWER SECTION:\n" );

        for(i=0 ; i < respuestasA ; i++)
        {
            if(query_type == T_A && ntohs(answer[i].resource->type) == T_A) /** T_A (IPv4) **/
            {
                long *p;
                p=(long*)answer[i].rdata;
                a.sin_addr.s_addr=(*p);
                printf(";%s.\tIN\tA\t%s\n",answer[i].name,inet_ntoa(a.sin_addr));
            }
            else if(query_type == T_MX && ntohs(answer[i].resource->type)==T_MX) /** MX **/
            {
                printf(";%s.\tIN\tMX\t%s\n",answer[i].name,answer[i].rdata);
            }
            else if(query_type == T_LOC) /** LOC **/
            {
                /**
                LOC ejemplo: systemadmin.es
                Respuesta del dig:
                ;; ANSWER SECTION:
                systemadmin.es.     3248    IN  LOC 41 24 0.499 N 2 10 52.530 E 47.00m 30m 10m 10m
                Del Wireshark:
                Version: 0                                  // 00 (hexadecimal)
                Size: 30 m                                  // 33
                Horizontal precision: 10 m                  // 13
                Vertical precision: 10 m                    // 13
                Latitude: 41 deg 24 min 0.499 sec N         // 88 e2 2d 73
                Longitude: 2 deg 10 min 52.530 sec E        // 80 77 d1 f2
                Altitude: 47 m                              // 00 98 a8 dc
                **/

                uint32_t latLit = ntohl(answerLOC->latitude);
                int32_t latval = (littleToBigEndian(latLit) - ((uint32_t)1<<31));
                uint32_t latdeg, latmin, latsec, latsecfrac;
                char northsouth;
                if (latval < 0)
                {
                    northsouth = 'S';
                    latval = -latval;
                }
                else
                    northsouth = 'N';

                latsecfrac = latval % 1000;
                latval = latval / 1000;
                latsec = latval % 60;
                latval = latval / 60;
                latmin = latval % 60;
                latval = latval / 60;
                latdeg = latval;

                uint32_t lonLit = ntohl(answerLOC->longitude);
                int32_t longval = (littleToBigEndian(lonLit) - ((uint32_t)1<<31));
                uint32_t longdeg, longmin, longsec, longsecfrac;
                char eastwest;
                if (longval < 0)
                {
                    eastwest = 'W';
                    longval = -longval;
                }
                else
                    eastwest = 'E';

                longsecfrac = longval % 1000;
                longval = longval / 1000;
                longsec = longval % 60;
                longval = longval / 60;
                longmin = longval % 60;
                longval = longval / 60;
                longdeg = longval;


                int altmeters, altfrac, altsign;
                int32_t altval;
                int referencealt = 100000 * 100;

                int32_t alt = littleToBigEndian(ntohl(answerLOC->altitude));

                if (alt < referencealt)   /* below WGS 84 spheroid */
                {
                    altval = referencealt - alt;
                    altsign = -1;
                }
                else
                {
                    altval = alt - referencealt;
                    altsign = 1;
                }
                altfrac = altval % 100;
                altmeters = (altval / 100) * altsign;

                printf(";%s.\tIN\tLOC\t %d %.2d %.2d.%.3d %c %d %d %.2d.%.3d %c %d.%.2dm %im %im %im\n",answer[i].name,latdeg, latmin, latsec, latsecfrac,northsouth,longdeg, longmin, longsec, longsecfrac,eastwest,altmeters,altfrac,precsize_ntoa(answerLOC->size),precsize_ntoa(answerLOC->horiz_pre),precsize_ntoa(answerLOC->vert_pre));

            }
            else if(query_type == T_NS && ntohs(answer[i].resource->type)==T_NS)
                printf(";%s.\tIN\tNS\t%s\n",answer[i].name,answer[i].rdata);
        }
    }
    /** imprime los RR authorities **/
    if (respuestasAU > 0 )
    {
        printf("\n;; AUTHORITY SECTION:\n" );

        for( i=0 ; i < respuestasAU ; i++)
        {
            printf(";%s.\tIN\t%s\t%s\n",authority[i].name,mapearTipo(ntohs(authority[i].resource->type)),authority[i].rdata);
        }
    }

    /** imprime los RR additional **/
    if (respuestasADD > 0 )
    {
        printf("\n;; ADDITIONAL SECTION:\n");
        for(i=0; i < respuestasADD ; i++)
        {
            if(ntohs(additional[i].resource->type)==T_A)    /** T_A (IPv4) **/
            {
                long *p;
                p=(long*)additional[i].rdata;
                a.sin_addr.s_addr=(*p);
                printf(";%s.\tIN\tA\t%s\n",additional[i].name,inet_ntoa(a.sin_addr));
            }
            if(ntohs(additional[i].resource->type)==28)
            {
                printf("ipv6!!!!\n");
            }

        }
    }
}


/**
 * En primera instancia crea una consulta con los datos suministrados.
 * Luego envía dicho paquete y recibe dentro del mismo "buffer" la respuesta.
 * Obtiene en estructuras definidas cada una de las respuestas (en sus 3 versiones).
 * Finalmente imprime el resultado.
 **/
int resolverConsulta(char *host , int query_type,struct RESOURCE_RECORD answer[],struct RESOURCE_RECORD authority[],struct RESOURCE_RECORD additional[],
                    struct R_DATA_LOC* answerLOC,int* respuestasA,int* respuestasAU,int* respuestasADD,int print)
{
    unsigned char mensajeDNS[65536],*qname,*reader;
    int i , j , stop , s;

    struct sockaddr_in dest;

    seccion_header *dns = NULL;
    seccion_question *qinfo = NULL;

    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);

    if (s < 0)
          {
            printf("*** ERROR - socket() falló ***\n");
            exit(-1);
          }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(puerto));
    dest.sin_addr.s_addr = inet_addr(servidorDNS);

    /** Me posiciono al comienzo del mensaje DNS y comienzo a "rellenar" la sección Header **/
    dns = (seccion_header *)&mensajeDNS;
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0;
    dns->opcode = 0; // query standard
    dns->aa = 0;
    dns->tc = 0; // este mensaje no está truncado
    if (strcmp(maneraConsulta,"-r")==0)
    {
        dns->rd = 1; /** Bit Recursion Desired **/
        dns->ra = 1;
    }
    else
    {
        dns->rd = 0;
        dns->ra = 0;
    }
    dns->z = 0;
    dns->rcode = 0;
    dns->qdcount = htons(1); // solo 1 consulta
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;
    /** Terminé de "rellenar" la sección Header **/

    /** Me posiciono al final de la sección Header del mensaje DNS y comienzo a "rellenar" la sección Question **/
    qname =(unsigned char*)&mensajeDNS[sizeof(seccion_header)];

    /** Inserto en qname, el host que me pasaron (si es solo un . debo preguntar por los servers root */
    cambiarAlFormatoNombreDNS(qname , host);

    qinfo =(seccion_question*)&mensajeDNS[sizeof(seccion_header) + (strlen((const char*)qname) + 1)];
    qinfo->qtype = htons(query_type);
    qinfo->qclass = htons(1);

    /** Terminé de "rellenar" la sección Question **/

    if( sendto(s,(char*)mensajeDNS,sizeof(seccion_header) + (strlen((const char*)qname)+1) + sizeof(seccion_question),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto error");
    }

    if(recvfrom (s,(char*)mensajeDNS , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom error");
    }

    dns = (seccion_header*) mensajeDNS;

    /** Me posiciono al final de la sección Question del mensaje DNS para comenzar a leer las respuestas del servidor DNS **/
    reader = &mensajeDNS[sizeof(seccion_header) + (strlen((const char*)qname)+1) + sizeof(seccion_question)];

    /** -------- COMIENZO A LEER LA SECCION ANSWER -------- **/

    /** descomentar para testear, cantidad de respuestas y sus tipos recibidas:
        printf("\nrespuestasA: %i\n",ntohs(dns->ancount));

        printf("\nrespuestasAU: %i\n",ntohs(dns->nscount));

        printf("\nrespuestasADD: %i\n",ntohs(dns->arcount));
    */
    stop=0;
    //repito tantas veces como "ancount" tenga, es decir la cantidad de respuestas
    for(i=0; i<ntohs(dns->ancount); i++)
    {
        *(respuestasA)+=1;
        //leo el nombre de la respuesta, en stop tengo el largo de dicho nombre
        answer[i].name=leerNombre(reader,mensajeDNS,&stop);
        reader = reader + stop;                             //stop indica el offset que debo sumar al punterlo reader

        /** obtengo el recurso, es decir, los datos de la respuesta **/

        answer[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);

        if(ntohs(answer[i].resource->type) == T_NS) { /** NS **/
            reader-=2;
            answer[i].rdata=leerNombre(reader,mensajeDNS,&stop);
            reader+=stop;

        }
        else if(ntohs(answer[i].resource->type) == T_A) /** T_A (IPv4) **/
        {   if(ntohs(dns->ancount)==1)reader-=2;         //si leo uno solo no tengo porque restarlo, problemas con leerNombre
            answer[i].rdata = (unsigned char*)malloc(ntohs(answer[i].resource->rdlength));

            for(j=0 ; j<ntohs(answer[i].resource->rdlength) ; j++)
            {
                answer[i].rdata[j]=reader[j];
            }

            answer[i].rdata[ntohs(answer[i].resource->rdlength)] = '\0';        // introduzco el caracter terminador

            reader = reader + ntohs(answer[i].resource->rdlength);              // agrego al reader un offset tan largo como el largo de los datos dentro del RR
        }
        else
            /** MX **/
            if(ntohs(answer[i].resource->type) == T_MX)
            {
                answer[i].rdata = leerNombre(reader,mensajeDNS,&stop);
                reader = reader + stop;
            }
            else
                /** -LOC **/
                if(ntohs(answer[i].resource->type) == T_LOC)
                {
                    answer[i].rdata = (unsigned char*)malloc(ntohs(answer[i].resource->rdlength));
                    reader = reader - 2;
                    int k = 0;
                    answerLOC->version =reader[k];
                    reader = reader + sizeof(answerLOC->version);
                    k = 0;
                    answerLOC->size =reader[k];
                    reader = reader + sizeof(answerLOC->size);
                    k = 0;
                    answerLOC->horiz_pre=reader[k];
                    reader = reader + sizeof(answerLOC->horiz_pre);
                    k = 0;
                    answerLOC->vert_pre=reader[k];
                    reader = reader + sizeof(answerLOC->vert_pre);
                    k = 0;
                    int oct1 = reader[k];
                    k++;
                    int oct2 = reader[k];
                    k++;
                    int oct3 = reader[k];
                    k++;
                    int oct4 = reader[k];
                    char lat[4]; /** 4 octetos = 4 bytes **/
                    /** Hexadecimal en string a partir de los octetos **/
                    sprintf(lat,"%.2x%.2x%.2x%.2x", oct1,oct2,oct3,oct4);
                    /** De string en hexa a entero de 32 bits **/
                    uint32_t latNum = ((uint32_t) strtoimax(lat, NULL, 16));
                    answerLOC->latitude = latNum;

                    reader = reader + sizeof(answerLOC->latitude);
                    k = 0;
                    oct1 = reader[k];
                    k++;
                    oct2 = reader[k];
                    k++;
                    oct3 = reader[k];
                    k++;
                    oct4 = reader[k];
                    char lon[4];
                    /** Hexadecimal en string a partir de los octetos **/
                    sprintf(lon,"%.2x%.2x%.2x%.2x", oct1,oct2,oct3,oct4);
                    /** De string en hexa a entero de 32 bits **/
                    int32_t lonNum = (int32_t)strtoimax(lon, NULL, 16);
                    answerLOC->longitude = lonNum;
                    reader = reader + sizeof(answerLOC->longitude);
                    k = 0;
                    oct1 = reader[k];
                    k++;
                    oct2 = reader[k];
                    k++;
                    oct3 = reader[k];
                    k++;
                    oct4 = reader[k];
                    char alt[4];
                    /** Hexadecimal en string a partir de los octetos **/
                    sprintf(alt,"%.2x%.2x%.2x%.2x", oct1,oct2,oct3,oct4);
                    /** De string en hexa a entero de 32 bits **/
                    uint32_t altNum = (uint32_t)strtoimax(alt, NULL, 16);
                    answerLOC->altitude = altNum;
                    reader = reader + sizeof(answerLOC->altitude);
                }
                else
                    if (strcmp(maneraConsulta,"-t")==0 && ntohs(answer[i].resource->type) == T_NS)
                    {
                        reader=reader - 2;

                        answer[i].rdata = leerNombre(reader,mensajeDNS,&stop);
                        reader = reader + stop;

                    }
    }

    /** -------- FIN LECTURA DE LA SECCION ANSWER -------- **/

    /** -------- COMIENZO A LEER LA SECCION AUTHORITY -------- **/

    for(i=0; i<ntohs(dns->nscount); i++)
    {

        *(respuestasAU)+=1;
        authority[i].name = leerNombre(reader,mensajeDNS,&stop);
        reader+=stop;

        authority[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        reader = reader - 2; // el readname nos deja corrido dos bytes

        authority[i].rdata = leerNombre(reader,mensajeDNS,&stop);
        reader+=stop;
    }

    /** -------- FIN LECTURA DE LA SECCION AUTHORITY -------- **/

    /** -------- COMIENZO A LEER LA SECCION ADDITIONAL -------- **/

    for(i=0; i<ntohs(dns->arcount); i++)
    {
        *(respuestasADD)+=1;
        additional[i].name=leerNombre(reader,mensajeDNS,&stop);
        reader+=stop;


        additional[i].resource=(struct R_DATA*)(reader);    // obtengo el recurso
        reader+=sizeof(struct R_DATA);
        reader-= 2;                                          // leer nombre nos deja dos bytes desfasados.

        if(ntohs(additional[i].resource->type)==T_A)          /** si es un T_A (IPv4) **/
        {
            additional[i].rdata = (unsigned char*)malloc(ntohs(additional[i].resource->rdlength));      // reservo espacio del tamaño del que recibo en dicho rdlength (del RR)
            for(j=0; j<ntohs(additional[i].resource->rdlength); j++)                                    // leo cada dato
                additional[i].rdata[j]=reader[j];

            additional[i].rdata[ntohs(additional[i].resource->rdlength)]='\0';      // caracter terminador
            reader+=ntohs(additional[i].resource->rdlength);                        // avanzo el puntero tanto como el tamaño del RR

        }
        else if(ntohs(additional[i].resource->type)==28){       //si es IPv6 lo ignoro, avanzo el largo del RR entero (avanzo el lector tantos bytes como largo del RR IPv6)
            reader+=ntohs(additional[i].resource->rdlength);
        }
        else
        {
            additional[i].rdata=leerNombre(reader,mensajeDNS,&stop);
            reader+=stop;
        }
    }
    /** limpio los RR con ipv6! **/
    int pos=0;
    for(i=0; i<ntohs(dns->arcount); i++){
        if(ntohs(additional[i].resource->type)==T_A){   //si es un ipv4 lo guardo al principio de los lugares disponibles y aumento la cuenta de ipv4 (pos)
            additional[pos]=additional[i];
            pos++;
        }
    }
    *respuestasADD = pos;

    /** -------- FIN LECTURA DE LA SECCION ADDITIONAL -------- **/


    if(print)printResults(answer,authority,additional,answerLOC,*respuestasA,*respuestasAU,*respuestasADD,host,query_type);
    return 0;
}






/**
 * Consulta iterativa
*/
void resolverConsultaIterativo (char *host , int query_type, struct R_DATA_LOC* answerLOC)
{
    //loc -t systemadmin.es no anda, le falta un paso. anda mal el ultimo paso aparentemente
    char* nombre;
    nombre = (char*) malloc(sizeof(char));
    strcpy(nombre,".");

    int largo = strlen(host);

    int terminar=0;
    int primero=1;
    int respuestasA = 0;
    int respuestasAU = 0;
    int respuestasADD = 0;
    while((respuestasA == 0)) {
        //printf("A CONSULTAR: %s SERVER DNS: %s\n",nombre,servidorDNS);
        struct RESOURCE_RECORD answer[20],authority[20],additional[20]; // Las respuestas del servidor DNS
        respuestasA = 0;
        respuestasAU = 0;
        respuestasADD = 0;
        if(primero){    //se debe ejecutar por primera vez siempre.
            resolverConsulta(".", T_NS, answer, authority, additional, answerLOC, &respuestasA, &respuestasAU, &respuestasADD,1);
            if(strcmp(host,".")!=0){
                respuestasA=0; //lo seteo en 0 asi vuelve a ciclar el while
            }
        }
        else //resuelvo la consulta normal
            resolverConsulta(host, query_type, answer, authority, additional, answerLOC, &respuestasA, &respuestasAU, &respuestasADD,1);

        //ya pase la primer consulta por rootservers! seteo el flag en 0.
            primero =0;

        if(respuestasA!=0){    //si encontre lo que buscaba tengo que dejar de buscar!
            if(ntohs(additional[0].resource->type)==query_type)
                terminar=1;
        }else{
            if((respuestasADD==0)&(respuestasA==0)){//si no tengo additional de donde tomar un ip, se lo pido al dns local desde el primer authority NS
                printf("\ndebo preguntar al server local\n");
                respuestasA = 0;
                respuestasAU = 0;
                respuestasADD = 0;
                maneraConsulta = "-r";
                servidorDNS = dns_servers[0];
                resolverConsulta((char*)authority[0].rdata, T_A, answer, authority, additional, answerLOC, &respuestasA, &respuestasAU, &respuestasADD,1);
                maneraConsulta = "-t";
                struct sockaddr_in a;
                long *p;
                p = (long*)answer[0].rdata;   //obtengo la primer respuesta y la uso de proximo server!
                a.sin_addr.s_addr = (*p);
                servidorDNS = inet_ntoa(a.sin_addr);
                respuestasA = 0;              //permite seguir a la recursion.
            }else{
                /** en servidorDNS esta el servidor donde se hace las consultas
                    si me dieron additional, obtengo el ip del primer server en additional[0],
                    para esto debo convertir a human readable el ip guardado ahi **/
                struct sockaddr_in a;
                long *p;
                p = (long*)additional[0].rdata;
                a.sin_addr.s_addr = (*p);
                servidorDNS = inet_ntoa(a.sin_addr);
            }

            if(largo ==0 ){
                terminar = 1;
                strcpy(nombre,host);
            }
            else{
                while((host[largo]!='.')&&(largo!=0))
                largo--;

                if(largo!=0)
                    largo++;

                strcpy(nombre,(host+largo));

                if(largo>1)
                    largo--;
                if(largo>0)
                    largo--;

                printf("\n");
            }
        }
        printf("\n");
    printf("-------------------------------------------------------------------------\n");
    }
    printf("\n");

}
/** FUNCION PRINCIPAL */
int main(int argc, char *argv[])
{
    get_dns_servers();          /** obtengo dns locales **/
    servidorDNS = dns_servers[0]; /** seteo el primero predefinido. **/

    if (argc > 1 && argc < 7 )
    {
        int errorParametrosExcluyentesTipoConsulta = 0;
        int errorParametrosExcluyentesManeraConsulta = 0;
        int modoAyuda = 0;
        int errorParametrosValidos = 0;
        char* hostname;
        if (argc == 2)
            if (strcmp(argv[1],"-h")==0)
                modoAyuda = 1;
        if (!modoAyuda)
        {
            hostname = argv[1];
        }
        if (argc > 2)
        {
            int ind = 2;
            if (argv[ind][0]=='@')   /** Se ingresó un servidor **/
            {
                int largoParametro = strlen(argv[ind]);

                char* aux;
                if ((aux=strchr(argv[ind],':'))!= NULL)   /** Chequeo si se ingresó puerto del servidor **/
                {
                    servidorDNS = cortarString(argv[ind],2,largoParametro-strlen(aux)-1);
                    puerto = cortarString(argv[ind],largoParametro-strlen(aux)+2,largoParametro);
                }
                else
                {
                    servidorDNS = cortarString(argv[ind],2,largoParametro);
                }
                ind++; /** aumentó el índice para próxima iteración para chequear argumentos **/
            }

            /** Chequeo de validación de parámetros **/
            int indice = ind;

            while (!errorParametrosValidos && indice < argc)
            {
                int chequeo = (strcmp(argv[indice],"-mx")==0) | (strcmp(argv[indice],"-t")==0) | (strcmp(argv[indice],"-r")==0) | (strcmp(argv[indice],"-a")==0) | (strcmp(argv[indice],"-loc")==0) | (strcmp(argv[indice],"-h")==0);
                if(!chequeo)
                    errorParametrosValidos = 1;
                indice++;
            }

            if (!errorParametrosValidos)
            {
                if (ind < argc && strcmp(argv[ind],"-a")==0)
                {
                    int indice = ind++;
                    while(!errorParametrosExcluyentesTipoConsulta && indice < argc)
                    {
                        if((strcmp(argv[indice],"-mx")==0) | (strcmp(argv[indice],"-loc")==0) )
                            errorParametrosExcluyentesTipoConsulta = 1;
                        indice++;
                    }
                }
                else if (ind < argc && strcmp(argv[ind],"-mx")==0)
                {
                    tipoConsulta = "-mx";
                    int indice = ind++;
                    while(!errorParametrosExcluyentesTipoConsulta && indice < argc)
                    {
                        if((strcmp(argv[indice],"-a")==0) | (strcmp(argv[indice],"-loc")==0) )
                            errorParametrosExcluyentesTipoConsulta = 1;
                        indice++;
                    }
                }
                else if (ind < argc && strcmp(argv[ind],"-loc")==0)
                {
                    tipoConsulta = "-loc";
                    int indice = ind++;
                    while(!errorParametrosExcluyentesTipoConsulta && indice < argc)
                    {
                        if((strcmp(argv[indice],"-mx")==0) | (strcmp(argv[indice],"-a")==0) )
                            errorParametrosExcluyentesTipoConsulta = 1;
                        indice++;
                    }
                }
                if (ind < argc && strcmp(argv[ind],"-r")==0)
                {
                    maneraConsulta = "-r";
                    int indice = ind++;
                    while(!errorParametrosExcluyentesManeraConsulta && indice < argc)
                    {
                        if(strcmp(argv[indice],"-t")==0)
                            errorParametrosExcluyentesManeraConsulta = 1;
                        indice++;
                    }
                }
                else if (ind < argc && strcmp(argv[ind],"-t")==0)
                {
                    maneraConsulta = "-t";
                    int indice = ind++;
                    while(!errorParametrosExcluyentesManeraConsulta && indice < argc)
                    {
                        if(strcmp(argv[indice],"-r")==0)
                            errorParametrosExcluyentesManeraConsulta = 1;
                        indice++;
                    }
                }
                if (ind < argc && strcmp(argv[ind],"-h")==0)
                    modoAyuda = 1;
            }
        }
        if (!errorParametrosValidos && !modoAyuda && !errorParametrosExcluyentesTipoConsulta && !errorParametrosExcluyentesManeraConsulta)
        {
            printf("Parámetro consulta = %s\n",hostname);
            printf("Parámetro Servidor = %s\n",servidorDNS);
            printf("Parámetro Puerto = %s\n",puerto);
            printf("Parámetro Tipo de Consulta = %s\n",tipoConsulta);
            printf("Parámetro Manera de Consulta = %s\n",maneraConsulta);

            // seteo las variables donde pongo las respuestas!
            struct RESOURCE_RECORD answer[20],authority[20],additional[20]; // Las respuestas del servidor DNS
            struct R_DATA_LOC* answerLOC = (struct R_DATA_LOC*) malloc(sizeof(struct R_DATA_LOC));

            // llevo cuenta de la cantidad de elementos dentro de cada arreglo:
            int respuestasA = 0;
            int respuestasAU = 0;
            int respuestasADD = 0;

            int query_type;
            if (strcmp(tipoConsulta,"-a")==0)
                query_type = T_A;
            else if (strcmp(tipoConsulta,"-mx")==0)
                query_type = T_MX;
            else
                query_type = T_LOC;

            if (strcmp(maneraConsulta,"-r")==0)
                resolverConsulta(hostname , query_type, answer, authority, additional, answerLOC,&respuestasA,&respuestasAU,&respuestasADD,1);
            else if (strcmp(maneraConsulta,"-t")==0)
            resolverConsultaIterativo(hostname , query_type, answerLOC);
        }
        else
        {
            if (modoAyuda)
                mostrarAyuda();
            else if (errorParametrosExcluyentesTipoConsulta || errorParametrosExcluyentesManeraConsulta)
                printf("ERROR: Ingresó parámetros excluyentes en el tipo o manera de consulta\n");
            else
                printf("ERROR: Ingresó parámetros no válidos\n");
        }
    }
    else
    {
        printf("ERROR: Ingresó una cantidad de parámetros no válida\n");
        mostrarAyuda();
    }
    return 0;
}
