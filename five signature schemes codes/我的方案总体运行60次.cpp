#include <pbc.h>
#include <pbc_test.h>
#include <time.h>
#define N 129
int main(int argc, char **argv) {
	
	pairing_t pairing;
	element_t s,r_ID,h1,d,x,h2,y,r,h3,t;
	element_t P,Ppub,K,Q,R;
	double T[60]={0},sum=0;
	int i;
	pbc_demo_pairing_init(pairing, argc, argv);
	element_init_Zr(s,pairing);//将变量初始化为Zr上的元素
	element_init_Zr(r_ID,pairing);
	element_init_Zr(h1, pairing);
	element_init_Zr(d, pairing);
	element_init_Zr(x, pairing);
	element_init_Zr(h2, pairing);
	element_init_Zr(y, pairing);
	element_init_Zr(r, pairing);
	element_init_Zr(h3, pairing);
	element_init_Zr(t, pairing);

	element_init_G1(P,pairing);//将变量初始化为G1上的元素
	element_init_G1(Ppub,pairing);
	element_init_G1(K,pairing);
	element_init_G1(Q,pairing);
	element_init_G1(R,pairing);
	
	element_t t_v,h1_v,h2_v,r_v,h3_v;
	element_t R_v,P_left,P_temp,P_rignt;
	element_init_Zr(t_v,pairing);
	element_init_Zr(h1_v,pairing);
	element_init_Zr(h2_v,pairing);
	element_init_Zr(r_v,pairing);
	element_init_Zr(h3_v,pairing);
	element_init_G1(R_v,pairing);
	element_init_G1(P_left,pairing);
	element_init_G1(P_temp,pairing);
	element_init_G1(P_rignt,pairing);
	
	clock_t begintime,endtime;
	for(i=0;i<60;i++){
	begintime=clock();	
	//计时开始
	//部分私钥提取
	element_random(s);
	element_random(P);
	element_mul_zn(Ppub,P,s);
	element_random(r_ID);
	element_mul_zn(K,P,r_ID);
	unsigned char K_bit[N]="0";
	element_to_bytes(K_bit, K);
	char ID_K[N+10]="0x0000006";
	strcat(ID_K,(const char *)K_bit);
	element_from_hash(h1,ID_K,strlen(ID_K));
	element_mul(d,s,h1);
	element_add(d,r_ID,d);
	//用户密钥生成
	element_random(x);
	element_mul_zn(Q,P,x);
	unsigned char Q_bit[N]="0";
	element_to_bytes(Q_bit, Q);
	char ID_K_Q[2*N+10]="0x0000006";
	strcat(ID_K_Q,(const char *)K_bit);
	strcat(ID_K_Q,(const char *)Q_bit);
	element_from_hash(h2,ID_K_Q,strlen(ID_K_Q));
	element_mul(y,x,h2);
	element_add(y,d,y);
	element_invert(y,y);
	
	//签名
	element_random(r);
	element_mul_zn(R,P,r);
	unsigned char R_bit[N]="0";
	element_to_bytes(R_bit, R);
	char m_ID_R_Q[3*N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *ID="0x0000006";
	strcat(m_ID_R_Q,ID);
	strcat(m_ID_R_Q,(const char *)R_bit);
	strcat(m_ID_R_Q,(const char *)Q_bit);
	element_from_hash(h3,m_ID_R_Q,strlen(m_ID_R_Q));
	element_mul(t,h3,x);
	element_add(t,t,r);
	element_mul(t,t,y);
	
	//验证签名
	element_set(R_v,R);
	element_set(t_v,t);
	unsigned char K_bit_v[N]="0";
	element_to_bytes(K_bit_v, K);
	char ID_K_v[N+10]="0x0000006";
	strcat(ID_K_v,(const char *)K_bit_v);
	element_from_hash(h1_v,ID_K_v,strlen(ID_K_v));
	unsigned char Q_bit_v[N]="0";
	element_to_bytes(Q_bit_v, Q);
	char ID_K_Q_v[2*N+10]="0x0000006";
	strcat(ID_K_Q_v,(const char *)K_bit_v);
	strcat(ID_K_Q_v,(const char *)Q_bit_v);
	element_from_hash(h2_v,ID_K_Q_v,strlen(ID_K_Q_v));
	
	element_mul_zn(P_left,Ppub,h1_v);
	element_add(P_left,P_left,K);
	element_mul_zn(P_temp,Q,h2_v);
	element_add(P_left,P_left,P_temp);
	element_mul_zn(P_left,P_left,t_v);
	
	unsigned char R_bit_v[N]="0";
	element_to_bytes(R_bit_v, R_v);
	char m_ID_R_Q_v[3*N]="abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *ID_v="0x0000006";
	strcat(m_ID_R_Q_v,ID_v);
	strcat(m_ID_R_Q_v,(const char *)R_bit_v);
	strcat(m_ID_R_Q_v,(const char *)Q_bit_v);
	element_from_hash(h3_v,m_ID_R_Q_v,strlen(m_ID_R_Q_v));

	element_mul_zn(P_rignt,Q,h3_v);
	element_add(P_rignt,R_v,P_rignt);

	bool isVerify=!element_cmp(P_left,P_rignt); 
	endtime = clock();	//计时结束
	if (isVerify)//只要签名正确那么就有P_left=P_rignt
		T[i]=(double)(endtime-begintime)/CLOCKS_PER_SEC;
	}

	//printf("\n");可根据T[i]是否为0判断验证是否成功
	for(i=0;i<60;i++)
		printf("%lf, ",T[i]);
	printf("\n");
	for(i=0;i<60;i++)
		sum+=T[i];
	printf("averagetime1=%lf\n",sum/60);
	
	element_clear(s);
	element_clear(r_ID);
	element_clear(h1);
	element_clear(d);
	element_clear(x);
	element_clear(h2);
	element_clear(y);
	element_clear(r);
	element_clear(h3);
	element_clear(t);
	element_clear(P);
	element_clear(Ppub);
	element_clear(K);
	element_clear(Q);
	element_clear(R);
	element_clear(R_v);
	element_clear(t_v);
	element_clear(h1_v);
	element_clear(h2_v);
	element_clear(r_v);
	element_clear(h3_v);
	element_clear(P_left);
	element_clear(P_temp);
	element_clear(P_rignt);
	return 0;
}