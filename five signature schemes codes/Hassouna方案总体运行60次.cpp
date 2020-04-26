#include <pbc.h>
#include <pbc_test.h>
#include <time.h>
#define N 129
int main(int argc, char **argv) {
	
	pairing_t pairing;
	element_t s,xm_1,xm_2,zm,tm;
	element_t P,Ppub,Xm,Km,Qm_1,Qm_2,Dm,Ym,Sm,Zm;
	double T[60]={0},sum=0;
	int i;

	pbc_demo_pairing_init(pairing, argc, argv);
	element_init_Zr(s,pairing);
	element_init_Zr(xm_1,pairing);//将变量初始化为Zr上的元素
	element_init_Zr(xm_2,pairing);
	element_init_Zr(zm,pairing);
	element_init_Zr(tm,pairing);
	element_init_G1(P,pairing);//将变量初始化为G1上的元素
	element_init_G1(Ppub,pairing);
	element_init_G1(Xm,pairing);
	element_init_G1(Km,pairing);
	element_init_G1(Qm_1,pairing);
	element_init_G1(Qm_2,pairing);
	element_init_G1(Dm,pairing);
	element_init_G1(Ym,pairing);
	element_init_G1(Sm,pairing);
	element_init_G1(Zm,pairing);

	element_t t1,t2;
	element_t MPm,MP1m;
	element_t a,sm;
	element_init_Zr(t1,pairing);
	element_init_Zr(t2,pairing);
	element_init_G1(MPm,pairing);
	element_init_G1(MP1m,pairing);
	element_init_GT(a,pairing);
	element_init_GT(sm,pairing);

	element_t MP1m_v,Qm_v,MPm_v;
	element_t sm_v,rm,e1,e2,e3;
	element_init_G1(MP1m_v,pairing);
	element_init_G1(Qm_v,pairing);
	element_init_G1(MPm_v,pairing);
	element_init_GT(sm_v,pairing);
	element_init_GT(rm,pairing);
	element_init_GT(e1,pairing);
	element_init_GT(e2,pairing);
	element_init_GT(e3,pairing);
	

	clock_t begintime,endtime;
	for(i=0;i<60;i++){
	begintime=clock();	//计时开始
	//生成密钥
	element_random(P);
	element_random(s);
	element_mul_zn(Ppub,P,s);

	char *ID_1="0x0000006";
	element_from_hash(Qm_1,ID_1,strlen(ID_1));
	element_mul_zn(Dm,Qm_1,s);
	element_random(xm_1);
	element_random(xm_2);
	element_mul_zn(Xm,P,xm_2);
	char *pass="mypassword_1234567";
	element_from_hash(zm,pass,strlen(pass));
	element_mul_zn(Km,P,zm);
	char *ID_2="0x0000006";
	element_from_hash(Qm_2,ID_2,strlen(ID_2));
	element_mul_zn(Ym,Qm_2,xm_2);
	element_add(tm,xm_1,zm);
	element_mul_zn(Sm,Dm,tm);
	element_mul_zn(Zm,P,xm_1);

	//sign the message
	element_random(a);
	char M[N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	element_from_hash(MPm,M,strlen(M));
	element_mul(t1,a,xm_1);
	element_mul_zn(MP1m,MPm,t1);
	pairing_apply(sm,MPm,Zm,pairing);
	element_mul(t2,a,xm_2);
	element_pow_zn(sm,sm,t2);
	
	//verify the sign
	element_set(sm_v,sm);
	element_set(MP1m_v,MP1m);
	char *ID_v="0x0000006";
	element_from_hash(Qm_v,ID_v,strlen(ID_v));
	pairing_apply(e1,Xm,Qm_v,pairing);
	pairing_apply(e2,Ym,P,pairing);
	if (!element_cmp(e1,e2))//If it holds(e1=e2) then user m’s public key is authentic
	{
		char M_v[N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		element_from_hash(MPm_v,M_v,strlen(M_v));
		pairing_apply(e3,MPm_v,Xm,pairing);
		if(!element_cmp(MP1m_v,MPm_v)||!element_cmp(sm,e3))
			printf("the signature is rejected！\n");
		else{
			pairing_apply(rm,MP1m_v,Xm,pairing);
			bool isVerify=!element_cmp(rm,sm_v); 
			endtime=clock();	//计时结束	
			if(isVerify)
				T[i]=(double)(endtime-begintime)/CLOCKS_PER_SEC;
		}
	}
	else
		printf("the signature is rejected！\n");
	}
	printf("\n");
	for(i=0;i<60;i++)
		printf("%lf, ",T[i]);//可根据T[i]是否为0判断验证是否成功
	printf("\n");
	for(i=0;i<60;i++)
		sum+=T[i];
	printf("averagetime=%lf\n",sum/60);

	element_clear(s);
	element_clear(xm_1);
	element_clear(xm_2);
	element_clear(zm);
	element_clear(tm);
	element_clear(P);
	element_clear(Ppub);
	element_clear(Xm);
	element_clear(Km);
	element_clear(Qm_1);
	element_clear(Qm_2);
	element_clear(Dm);
	element_clear(Ym);
	element_clear(Sm);
	element_clear(Zm);
	element_clear(t1);
	element_clear(t2);
	element_clear(MPm);
	element_clear(MP1m);
	element_clear(a);
	element_clear(sm);
	element_clear(MPm_v);
	element_clear(MP1m_v);
	element_clear(Qm_v);
	element_clear(sm_v);
	element_clear(rm);
	element_clear(e1);
	element_clear(e2);
	element_clear(e3);
	pairing_clear(pairing);
	
	return 0;
}