#include <pbc.h>
#include <pbc_test.h>
#include <time.h>
#define N 129
int main(int argc, char **argv) {
	pairing_t pairing;
	element_t s,x_s,r_s,h1_s,h0_1,k_s,h0_2,d_s;
	element_t P,P_KGC,X_s,R_s,P_temp1,P_temp2;
	element_t Y;
	double T1[60],T2[60]={0},sum1=0,sum2=0;
	int i;

	pbc_demo_pairing_init(pairing, argc, argv);
	element_init_Zr(s,pairing);//将变量初始化为Zr上的元素
	element_init_Zr(x_s,pairing);
	element_init_Zr(r_s,pairing);
	element_init_Zr(h1_s,pairing);
	element_init_Zr(h0_1,pairing);
	element_init_Zr(k_s,pairing);
	element_init_Zr(h0_2,pairing);
	element_init_Zr(d_s,pairing);
	element_init_G1(P,pairing);//将变量初始化为G1上的元素
	element_init_G1(P_KGC,pairing);
	element_init_G1(X_s,pairing);
	element_init_G1(R_s,pairing);
	element_init_G1(P_temp1,pairing);
	element_init_G1(P_temp2,pairing);
	element_init_GT(Y,pairing);//将变量初始化为GT上的元素

	element_t h2_s,t,temp;
	element_t delta;
	element_init_Zr(h2_s,pairing);
	element_init_Zr(t,pairing);
	element_init_Zr(temp,pairing);
	element_init_G1(delta,pairing);
	
	element_t t_v,h1s_v,h2s_v;
	element_t delta_v,Ptemp1_v,Ptemp2_v;
	element_t Y_v;
	element_init_Zr(t_v,pairing);
	element_init_Zr(h1s_v,pairing);
	element_init_Zr(h2s_v,pairing);
	element_init_G1(delta_v,pairing);
	element_init_G1(Ptemp1_v,pairing);
	element_init_G1(Ptemp2_v,pairing);
	element_init_GT(Y_v,pairing);

	//部分私钥提取
	element_random(s);
	element_random(P);
	element_mul_zn(P_KGC,P,s);//计算P_KGC=sP
	pairing_apply(Y,P,P,pairing);

	element_random(x_s);
	element_mul_zn(X_s,P,x_s);//计算X_s=(x_s)P

	element_random(r_s);
	element_mul_zn(R_s,P,r_s);//计算R_s=(r_s)P
	char ID_Xs_Rs[2*N+12]="0x0000006";
	unsigned char Xs_bit[N]="0";
	element_to_bytes(Xs_bit,X_s);
	strcat(ID_Xs_Rs,(const char *)Xs_bit);
	unsigned char Rs_bit[N]="0";
	element_to_bytes(Rs_bit,R_s);
	strcat(ID_Xs_Rs,(const char *)Rs_bit);
	element_from_hash(h1_s,ID_Xs_Rs,strlen(ID_Xs_Rs));//计算h1_s=H1(ID,X_s,R_s)
	element_mul_zn(P_temp1,X_s,s);
	unsigned char sXs_bit[N]="0";
	element_to_bytes(sXs_bit,P_temp1);
	element_from_hash(h0_1,sXs_bit,strlen((const char *)sXs_bit));//计算h0_1=H0(sX_s)
	element_mul(k_s,s,h1_s);
	element_add(k_s,r_s,k_s);
	element_add(k_s,h0_1,k_s);
	
	element_mul_zn(P_temp2,P_KGC,x_s);
	unsigned char x_sP_KGC_bit[N]="0";
	element_to_bytes(x_sP_KGC_bit,P_temp2);
	element_from_hash(h0_2,x_sP_KGC_bit,strlen((const char *)x_sP_KGC_bit));//计算h0_2=H0((x_s)P_KGC)
	element_sub(d_s,k_s,h0_2);

	clock_t begintime1,endtime1;
	clock_t begintime2,endtime2;
	for(i=0;i<60;i++){
	//签名
	begintime1=clock();	//计时开始

	char m_IDs[N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char ID_s[N]="0x0000006";
	strcat(m_IDs,ID_s);
	element_from_hash(h2_s,m_IDs,strlen(m_IDs));//计算h2=H2(m,ID_s)

	element_random(t);
	element_mul(temp,x_s,t);
	element_add(temp,temp,d_s);
	element_add(temp,temp,h2_s);
	element_invert(temp,temp);
	element_mul_zn(delta,P,temp);//计算delta
	endtime1=clock();	//计时结束	
	T1[i]=(double)(endtime1-begintime1)/CLOCKS_PER_SEC;
	
	
	
	//验证签名
	begintime2=clock();	//计时开始
	element_set(t_v,t);
	element_set(delta_v,delta);

	char ID_Xs_Rs_v[2*N+12]="0x0000006";
	unsigned char Xs_bit_v[N]="0";
	element_to_bytes(Xs_bit_v,X_s);
	strcat(ID_Xs_Rs_v,(const char *)Xs_bit_v);
	unsigned char Rs_bit_v[N]="0";
	element_to_bytes(Rs_bit_v,R_s);
	strcat(ID_Xs_Rs_v,(const char *)Rs_bit_v);
	element_from_hash(h1s_v,ID_Xs_Rs_v,strlen(ID_Xs_Rs_v));//计算h1_s=H1(ID,X_s,R_s)
	char m_IDs_v[N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char ID_s_v[N]="0x0000006";
	strcat(m_IDs_v,ID_s_v);
	element_from_hash(h2s_v,m_IDs_v,strlen(m_IDs_v));//计算h2_s=H2(m,ID_s)
	

	element_mul_zn(Ptemp1_v,X_s,t_v);
	element_add(Ptemp1_v,Ptemp1_v,R_s);
	element_mul_zn(Ptemp2_v,P_KGC,h1s_v);
	element_add(Ptemp1_v,Ptemp1_v,Ptemp2_v);
	element_mul_zn(Ptemp2_v,P,h2s_v);
	element_add(Ptemp1_v,Ptemp1_v,Ptemp2_v);
	pairing_apply(Y_v,delta_v,Ptemp1_v,pairing);
	
	bool isVerify=!element_cmp(Y_v,Y); 
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


	element_clear(s);
	element_clear(x_s);
	element_clear(r_s);
	element_clear(h1_s);
	element_clear(h0_1);
	element_clear(k_s);
	element_clear(h0_2);
	element_clear(d_s);
	element_clear(P);
	element_clear(P_KGC);
	element_clear(X_s);
	element_clear(R_s);
	element_clear(P_temp1);
	element_clear(P_temp2);
	element_clear(Y);
	element_clear(h2_s);
	element_clear(t);
	element_clear(temp);
	element_clear(delta);
	element_clear(t_v);
	element_clear(h1s_v);
	element_clear(h2s_v);
	element_clear(delta_v);
	element_clear(Ptemp1_v);
	element_clear(Ptemp2_v);
	element_clear(Y_v);
	pairing_clear(pairing);

	return 0;
}