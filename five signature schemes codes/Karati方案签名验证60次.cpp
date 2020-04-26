#include <pbc.h>
#include <pbc_test.h>
#include <time.h>
#define N 129
int main(int argc, char **argv) {
	pairing_t pairing;
	element_t L,r,h1,y,x_s,temp,t,h2,z;
	element_t P,Ppub,R_s,Q_s1,Q_s2,T;
	double T1[60],T2[60]={0},sum1=0,sum2=0;
	int i;

	pbc_demo_pairing_init(pairing, argc, argv);
	element_init_Zr(L,pairing);//将变量初始化为Zr上的元素
	element_init_Zr(r,pairing);
	element_init_Zr(h1, pairing);
	element_init_Zr(y, pairing);
	element_init_Zr(x_s, pairing);
	element_init_Zr(temp, pairing);
	element_init_Zr(t, pairing);
	element_init_Zr(h2, pairing);
	element_init_Zr(z, pairing);
	element_init_G1(P,pairing);//将变量初始化为G1上的元素
	element_init_G1(Ppub,pairing);
	element_init_G1(R_s,pairing);
	element_init_G1(Q_s1,pairing);
	element_init_G1(Q_s2,pairing);
	element_init_G1(T,pairing);
	
	element_t z_v,h1_v,h2_v;
	element_t T_v,Temp,P_rignt;
	element_init_Zr(z_v,pairing);
	element_init_Zr(h1_v,pairing);
	element_init_Zr(h2_v,pairing);
	element_init_G1(T_v,pairing);
	element_init_G1(Temp,pairing);
	element_init_G1(P_rignt,pairing);
	
	
	
	//部分私钥提取
	element_random(L);
	element_random(P);
	element_mul_zn(Ppub,P,L);//计算Ppub=LP
	
	element_random(r);
	element_mul_zn(R_s,P,r);//计算R_s=rP
	
	char IDs_Rs_P[2*N+10]="0x0000006";
	unsigned char Rs_bit[N]="0";
	element_to_bytes(Rs_bit, R_s);
	strcat(IDs_Rs_P,(const char*)Rs_bit);
	unsigned char P_bit[N]="0";
	element_to_bytes(P_bit, P);
	strcat(IDs_Rs_P,(const char*)P_bit);
	element_from_hash(h1,IDs_Rs_P,strlen(IDs_Rs_P));//计算h1=H(ID_s,R_s,P)
	
	element_invert(temp,L);
	element_mul_zn(Q_s1,P,temp);
	element_mul_zn(Q_s1,Q_s1,r);
	element_invert(r,r);
	element_mul(r,L,r);
	element_mul(r,h1,r);
	element_add(y,r,temp);
	
	element_random(x_s);
	element_mul_zn(Q_s2,R_s,x_s);//计算Q_s2=(x_s)R_s
	
	clock_t begintime1,endtime1;
	clock_t begintime2,endtime2;
	for(i=0;i<60;i++){
	//签名
	begintime1=clock();	//计时开始
	element_random(t);
	element_mul_zn(T,R_s,t);//计算T=tR_s

	char m_IDs_T_Qs1[3*N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char IDs[N]="0x0000006";
	strcat(m_IDs_T_Qs1,IDs);
	unsigned char T_bit[N]="0";
	element_to_bytes(T_bit, T);
	strcat(m_IDs_T_Qs1,(const char *)T_bit);
	unsigned char Qs1_bit[N]="0";
	element_to_bytes(Qs1_bit, Q_s1);
	strcat(m_IDs_T_Qs1,(const char *)Qs1_bit);
	element_from_hash(h2,m_IDs_T_Qs1,strlen(m_IDs_T_Qs1));//计算v=H(m,ID,T,Q_s1)
	
	element_mul(z,h2,x_s);
	element_add(z,z,y);
	element_add(z,z,t);
	element_invert(z,z);
	element_mul(z,z,x_s);//计算z
	
	//计时结束
	endtime1 = clock();		
	T1[i]=(double)(endtime1-begintime1)/CLOCKS_PER_SEC;
	

	//验证签名
	begintime2=clock();//计时开始	
	element_set(T_v,T);
	element_set(z_v,z);
	
	char IDs_Rs_P_v[2*N+10]="0x0000006";
	unsigned char Rs_bit_v[N]="0";
	element_to_bytes(Rs_bit_v, R_s);
	strcat(IDs_Rs_P_v,(const char*)Rs_bit_v);
	unsigned char P_bit_v[N]="0";
	element_to_bytes(P_bit_v, P);
	strcat(IDs_Rs_P_v,(const char*)P_bit_v);
	element_from_hash(h1_v,IDs_Rs_P_v,strlen(IDs_Rs_P_v));//计算h1=H(ID_s,R_s,P)
	char m_IDs_T_Qs1_v[3*N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char IDs_v[N]="0x0000006";
	strcat(m_IDs_T_Qs1_v,IDs_v);
	unsigned char T_bit_v[N]="0";
	element_to_bytes(T_bit_v, T_v);
	strcat(m_IDs_T_Qs1_v,(const char *)T_bit_v);
	unsigned char Qs1_bit_v[N]="0";
	element_to_bytes(Qs1_bit_v, Q_s1);
	strcat(m_IDs_T_Qs1_v,(const char *)Qs1_bit_v);
	element_from_hash(h2_v,m_IDs_T_Qs1_v,strlen(m_IDs_T_Qs1_v));//计算v=H(m,ID,T,Q_s1)

	element_mul_zn(P_rignt,Ppub,h1_v);
	element_add(P_rignt,P_rignt,Q_s1);
	element_add(P_rignt,P_rignt,T);
	element_mul_zn(Temp,Q_s2,h2_v);
	element_add(P_rignt,P_rignt,Temp);
	element_mul_zn(P_rignt,P_rignt,z);

	bool isVerify=!element_cmp(Q_s2,P_rignt); 
	endtime2=clock();//计时结束
	if(isVerify)
		T2[i]=(double)(endtime2-begintime2)/CLOCKS_PER_SEC;
	}
	printf("\n");
	//for(i=0;i<60;i++)
		//printf("%lf, ",T1[i]);
	//printf("\n");
	for(i=0;i<60;i++)
		printf("%lf, ",T2[i]);//可根据T2[i]是否为0判断验证是否成功
	printf("\n");
	for(i=0;i<60;i++){
		sum1+=T1[i];
		sum2+=T2[i];
	}
	printf("averagetime1=%lf	averagetime2=%lf\n",sum1/60,sum2/60);


	element_clear(L);
	element_clear(r);
	element_clear(h1);
	element_clear(y);
	element_clear(x_s);
	element_clear(temp);
	element_clear(t);
	element_clear(h2);
	element_clear(z);
	element_clear(P);
	element_clear(Ppub);
	element_clear(R_s);
	element_clear(Q_s1);
	element_clear(Q_s2);
	element_clear(T);
	element_clear(z_v);
	element_clear(h1_v);
	element_clear(h2_v);
	element_clear(T_v);
	element_clear(Temp);
	element_clear(P_rignt);
	

	return 0;
}