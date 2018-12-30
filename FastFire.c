/*
  @author <Ali Ghalambaz>
  @Email(1) : aghalambaz@gmail.com
  @date     : 2011/22/11
  @licence MIT
 */
#include <linux/module.h>                   /*module*/
#include <linux/kernel.h>                   /*printk()*/
#include <linux/fs.h>                       /*file reading*/
#include <linux/netfilter.h>                /*packet capturing*/
#include <linux/netfilter_ipv4.h>           /*packet capturing*/
#include <linux/skbuff.h>                   /*Networking-packet structure*/
#include <linux/tcp.h>                      /*Networking-trasport header ports*/
#include <linux/ip.h>                       /*Networking-network header (ip)*/
#include <linux/if_ether.h>                 /*Networking-(mac header)not used!*/
#include <linux/vmalloc.h>                  /*virtual memory allocation*/
#include <linux/in.h>                       /*protocols*/
#include <linux/netdevice.h>

/*____________________________________Define_________________________________*/
#define BUFFER_READ 256  //Buffer(Characters) in File Reading 
/*____________________________________Statics________________________________*/
char buffer[BUFFER_READ];
static int ips;
static struct nf_hook_ops hook_ops_pre;
struct tcphdr *tcp_header;
struct iphdr *ip_header;
struct ethhdr *eth_hd;
unsigned int sadd,oct1,oct2,oct3,oct4,dport,dadd;
unsigned short int poroto;
unsigned char *o1,*o2,*o3,*o4,*o5,*o6;

/*____________________________________porto_type____________________________*/
static int add_node(unsigned int);
static void pre_init(int);
/*____________________________________Structs________________________________*/
union ip_format
{
    unsigned short int octet[4];
    unsigned int ip_all_bits;
    unsigned int part1:16,part2:16;
}ip;
/*____________________________________________*/
struct node_iplookup //Searching For ip in linklist in RAM(memory)
{
    struct node_iplookup *right;
    union ip_format ip;
}
ex_node,*ip_ptr,*ip_i_ptr;
struct node_iplookup fire_iphdl; //Firewall ip header link list
/*____________________________________________*/
struct port_table //all ports that will be closed can set here   //example    port[3306] = 0xff ; 3306 is now closed
{
    unsigned int port[65537];
}fire_prttbl; //Firewall Port Table
/*____________________________________________*/

/*____________________________________Functions_____________p1____list___*/
static void pre_init(int i)
{
    ip_ptr = NULL;
    ips=0;
    do
    {
        fire_prttbl.port[i] = NULL;
    }while(++i<65536);
}

static int alloc_node(void) //every ip that read from file insert in a node in link list
{
    ip_ptr = vmalloc(sizeof(ex_node));
    if(!ip_ptr)
    {
            return 0;
    }
    ip_ptr->right = 0xffffffff;
            return 1;

}
static inline int add_node(unsigned int ip_int)
{
    if(alloc_node()==0)
    {
        printk(KERN_INFO"Node Allocation Failed!\n");
        return 0;
    }
    if(ips == 0)
    {
        printk(KERN_INFO"null  2\n");
        fire_iphdl.right=(struct node_iplookup *)ip_ptr;
        ips++;
    }
    else
    {
        ips++;
        ip_i_ptr = fire_iphdl.right;
        while(ip_i_ptr != 0xffffffff)
        {
            ip_i_ptr = ip_i_ptr->right;
        }
        ip_i_ptr =(struct node_iplookup *)ip_ptr;
    }
    ip_ptr->ip.ip_all_bits = ip_int;
    return 1;
}

/*____________________________________Functions_____________p2_____file_____*/
static int char_to_int(char *c)
{
    return c-48;
}
static inline int analysis_ip(char buffer[]) //reading ip in text format and convert in usable ip format 
{
    __u32 i=0;
    unsigned int ip_int=0;
    __u32 temp=0;
    __u32 shift=24;
    for(i=0;i<BUFFER_READ;i++)
    {
        while(char_to_int(buffer[i])>= 0)    /* >0 manzor -2 == . */
        {
            temp=temp*10+char_to_int(buffer[i]);
            i++;
        }
        ip_int|=temp<<shift;
        shift=shift-8;
        temp =0 ;
        if(buffer[i]-48 == -38 )          /* -38 == ENTER */
        {
            if(add_node(ip_int)<=0) /*function part 1*/
            {
              printk(KERN_INFO"Node Add Failed!\n");
              return 0;
            }
            ip_int=0;
            shift =24;
        }
        if(buffer[i]-48 == -48 ) break;   /* -48 == NULL */
    }
    return 1;
}

static inline set_port(unsigned int port) //close port
{
    fire_prttbl.port[port]=0xffffffff;
    return 1;
}
static inline int analysis_port(char buffer[])
{
    __u32 i=0;
    unsigned int port_int=0;
    __u32 temp=0;
    for(i=0;i<BUFFER_READ;i++)
    {
        while(char_to_int(buffer[i])>= 0)    /* >0 it means -2 == . */
        {
            port_int=port_int*10+char_to_int(buffer[i]);
            i++;
        }
        if(buffer[i]-48 == -38 )          /* -38 == ENTER */
        {
            if(set_port(port_int)<=0) /*function part 1*/
            {
              printk(KERN_INFO"port set Failed!\n");
              return 0;
            }
            port_int =0;
        }
        if(buffer[i]-48 == -48 ) break;   /* -48 == NULL */
    }
    return 1;
}
static inline int port_lookup(unsigned int port)
{
    if(fire_prttbl.port[port]== 0xffffffff)
    {
        return 1;
    }
    return 0;
}


static inline int file_read(char file_path[])    //Reading File
{
    struct file *f;
    mm_segment_t fs;
    int i;
    for(i=0;i<BUFFER_READ;i++)
        buffer[i] = NULL;
    f = filp_open(file_path, O_RDONLY, 0);
    if(f == NULL)
    {
        printk(KERN_ALERT "filp_open error!!.\n");
        return 0;
    }
    else{
        fs = get_fs();
        set_fs(get_ds());
        f->f_op->read(f, buffer,BUFFER_READ, &f->f_pos);
        set_fs(fs);
    }
    filp_close(f,NULL);
    return 1;
}

static inline struct node_iplookup * ip_lookup(unsigned int ip_lookfor)
{
    if(ips == 0) return NULL;
    ip_i_ptr = fire_iphdl.right;
    while(ip_i_ptr != 0xffffffff)
    {
        if(ip_i_ptr->ip.ip_all_bits == ip_lookfor) return ip_i_ptr;
        ip_i_ptr = ip_i_ptr->right;
    }
    return NULL;
}



unsigned int capture_filter(
unsigned int hooknum,
struct sk_buff *skb,
const struct net_device *in,
const struct net_device *out,
int (*okfn)(struct sk_buff*))
{
    ip_header = (struct iphdr *)skb->network_header;
    eth_hd =(struct ethhdr *)skb->mac_header;
    /*tcp_header = (struct tcphdr *)skb->network_header;*/
    /*ip_header->daddr = 3433221222;*/  //Example is just for changing Destination Address 

    if(skb->mac_len > 0)
    {
        o1 = eth_hd->h_source[0];
        o2 = eth_hd->h_source[1];
        o3 = eth_hd->h_source[2];
        o4 = eth_hd->h_source[3];
        o5 = eth_hd->h_source[4];
        o6 = eth_hd->h_source[5];
        printk(KERN_INFO"Recieve :Source_MAC:%0X.%0X.%0X.%0X.%0X.%0X \n",o1,o2,o3,o4,o5,o6);
        o1 = eth_hd->h_dest[0];
        o2 = eth_hd->h_dest[1];
        o3 = eth_hd->h_dest[2];
        o4 = eth_hd->h_dest[3];
        o5 = eth_hd->h_dest[4];
        o6 = eth_hd->h_dest[5];
        printk(KERN_INFO"Recieve Dest_Mac:%0x.%0x.%0x.%0x.%0x.%0x \n",o1,o2,o3,o4,o5,o6);
    }
    else
    {

        printk(KERN_INFO"Send----: Mac Not Found\n");
        sadd= ip_header->saddr;
        oct1=(255 & sadd);
        oct2=(0xff00 & sadd)>>8;
        oct3=(0xff0000 & sadd)>>16;
        oct4=(0xff000000 & sadd)>>24;
        printk(KERN_INFO"NO_MAC_Send :Source_IP:%u.%u.%u.%u\n",oct1,oct2,oct3,oct3);
        sadd= ip_header->daddr;
        oct1=(255 & sadd);
        oct2=(0xff00 & sadd)>>8;
        oct3=(0xff0000 & sadd)>>16;
        oct4=(0xff000000 & sadd)>>24;
        printk(KERN_INFO"NO_MAC_Send Dest_IP:%u.%u.%u.%u\n",oct1,oct2,oct3,oct3);
        return NF_ACCEPT;

    }
    sadd= ip_header->saddr;
    oct1=(255 & sadd);
    oct2=(0xff00 & sadd)>>8;
    oct3=(0xff0000 & sadd)>>16;
    oct4=(0xff000000 & sadd)>>24;
    printk(KERN_INFO"Send :Source_IP:%u.%u.%u.%u\n",oct1,oct2,oct3,oct3);
    sadd= ip_header->daddr;
    oct1=(255 & sadd);
    oct2=(0xff00 & sadd)>>8;
    oct3=(0xff0000 & sadd)>>16;
    oct4=(0xff000000 & sadd)>>24;
    printk(KERN_INFO"Send Dest_IP:%u.%u.%u.%u\n",oct1,oct2,oct3,oct3);
    return NF_ACCEPT;

}



/*____________________________________main______________________________*/
int init_module(void)
{
    printk(KERN_INFO "Starting Module...\n");
    file_read("/ip.txt");   /*reading ip's from file in this path /ip.txt */

    if(analysis_ip(&buffer)<=0)
    {
        fire_iphdl.ip.ip_all_bits = 0xffffffff;
        printk(KERN_INFO"Analysis ip Faild!\n");
        return 0;
    }

    file_read("/port.txt");   /*reading port's from file in this path /port.txt */
    if(analysis_port(&buffer)<=0)
    {
        printk(KERN_INFO"Analysis port Faild!\n");
        return 0;
    }
    printk(KERN_INFO"Analysis port Successful\n");
    printk(KERN_INFO "Reading Files Successful\n");
    /*if(ip_lookup(3232235747))
    {
        printk(KERN_INFO "IP Found!\n");
		Now you can Drop it!
    }
    else
    {
        printk(KERN_INFO "IP not Found!\n");
    }*/
    /*if(port_lookup(11)==1)
        {
            printk(KERN_INFO "OPEN PORT\n");
        }
        else
        {
            printk(KERN_INFO "PORT CLOSED!\n");
        }
    return 0;*/
      printk(KERN_INFO "Registering Hook!\n");
        hook_ops_pre.hook = capture_filter;
        hook_ops_pre.hooknum = NF_INET_PRE_ROUTING;
        hook_ops_pre.pf = NFPROTO_IPV4;
        hook_ops_pre.priority = NF_IP_PRI_FIRST;
        nf_register_hook(&hook_ops_pre);
      printk(KERN_INFO "Registering Hook Finished!\n");

}
void cleanup_module(void)
{
    nf_unregister_hook(&hook_ops_pre);
    printk(KERN_INFO "Closing Finished\n");
}
