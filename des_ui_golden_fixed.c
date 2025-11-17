/* des_ui_golden_fixed.c
   DES ncurses UI with golden title + shooting stars + theme toggle
   Compile:
     sudo apt install libncurses5-dev libssl-dev
     gcc des_ui_golden_fixed.c -o desfile -lcrypto -lncurses
   Run:
     ./desfile
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <ncurses.h>
#include <stdarg.h>

#define HEADER_TAG "DESENC"
#define HEADER_LEN 6
#define KEY_LEN 8
#define BUF_SZ 4096
#define MAX_STARS 50

typedef enum { THEME_T1, THEME_T1_ALT } theme_t;
typedef struct { int x, y, speed, counter; } star_t;
static star_t stars[MAX_STARS];

/* Utilities */
static void centered_mvprintw(int row, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    int cols = COLS;
    int start = (cols - (int)strlen(buf)) / 2;
    if (start < 0) start = 0;
    mvprintw(row, start, "%s", buf);
}
static void draw_clock(void) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    char s[64];
    snprintf(s,sizeof(s),"%02d:%02d:%02d",tm->tm_hour,tm->tm_min,tm->tm_sec);
    mvprintw(1,COLS-(int)strlen(s)-2,"%s",s);
}
static void draw_progress(WINDOW *w,double fraction,theme_t theme){
    int wcols=getmaxx(w);
    int bar_w=(wcols-20)>20? wcols-20:20;
    int x0=(wcols-bar_w)/2;
    int y=getmaxy(w)/2;
    int filled=(int)(fraction*bar_w+0.5);
    if(filled<0) filled=0; if(filled>bar_w) filled=bar_w;
    mvwprintw(w,y-1,x0-2,"["); mvwprintw(w,y-1,x0+bar_w+1,"]");
    for(int i=0;i<bar_w;i++){
        if(i<filled){ wattron(w,COLOR_PAIR(3)); mvwprintw(w,y-1,x0+i," "); wattroff(w,COLOR_PAIR(3)); }
        else mvwprintw(w,y-1,x0+i,"-");
    }
    mvwprintw(w,y+1,x0,"Progress: %3d%%",(int)(fraction*100.0));
    wrefresh(w);
}
static void show_status(WINDOW *w,const char *msg,theme_t theme){
    int h=getmaxy(w),wcols=getmaxx(w);
    int y=h-3,x=(wcols-(int)strlen(msg))/2;if(x<1)x=1;
    if(theme==THEME_T1) wattron(w,COLOR_PAIR(2)|A_BOLD);
    else wattron(w,COLOR_PAIR(5)|A_BOLD);
    mvwprintw(w,y,x,"%-*s",wcols-2*x,msg);
    if(theme==THEME_T1) wattroff(w,COLOR_PAIR(2)|A_BOLD);
    else wattroff(w,COLOR_PAIR(5)|A_BOLD);
    wrefresh(w);
}
static void sound_alert_ok(void){beep();}
static void sound_alert_err(void){beep(); napms(80); beep();}
static OSSL_PROVIDER *load_legacy_provider(void){
    OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();
    return OSSL_PROVIDER_load(NULL,"legacy");
}

/* Encrypt/Decrypt functions (unchanged, same as before) */
static int encrypt_path_with_key(WINDOW *w,const char *path,const unsigned char key[KEY_LEN],theme_t theme){
    FILE *fin=fopen(path,"rb"); if(!fin){ show_status(w,"Cannot open input file",theme); return -1;}
    char hdr[HEADER_LEN]; size_t rr=fread(hdr,1,HEADER_LEN,fin);
    if(rr==HEADER_LEN && memcmp(hdr,HEADER_TAG,HEADER_LEN)==0){ fclose(fin); show_status(w,"File already encrypted",theme); return -2;}
    fseek(fin,0,SEEK_END); uint64_t orig_size=(uint64_t)ftell(fin); rewind(fin);
    char tmp[1024]; snprintf(tmp,sizeof(tmp),"%s.des.tmp",path);
    FILE *fout=fopen(tmp,"wb"); if(!fout){ fclose(fin); show_status(w,"Cannot create temp file",theme); return -1;}
    fwrite(HEADER_TAG,1,HEADER_LEN,fout); fwrite(&orig_size,sizeof(orig_size),1,fout);
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); EVP_EncryptInit_ex(ctx,EVP_des_ecb(),NULL,key,NULL);
    unsigned char inbuf[BUF_SZ],outbuf[BUF_SZ+EVP_MAX_BLOCK_LENGTH]; int outlen=0;
    size_t n; uint64_t processed=0;
    while((n=fread(inbuf,1,sizeof(inbuf),fin))>0){
        EVP_EncryptUpdate(ctx,outbuf,&outlen,inbuf,(int)n); fwrite(outbuf,1,outlen,fout);
        processed+=n; draw_progress(w,(double)processed/(double)orig_size,theme);
    }
    EVP_EncryptFinal_ex(ctx,outbuf,&outlen); if(outlen>0) fwrite(outbuf,1,outlen,fout);
    EVP_CIPHER_CTX_free(ctx); fclose(fin); fclose(fout); remove(path); rename(tmp,path);
    sound_alert_ok(); show_status(w,"Encryption successful",theme); return 0;
}
static int decrypt_path_with_key(WINDOW *w,const char *path,const unsigned char key[KEY_LEN],theme_t theme){
    FILE *fin=fopen(path,"rb"); if(!fin){ show_status(w,"Cannot open file",theme); return -1;}
    char tag[HEADER_LEN]; fread(tag,1,HEADER_LEN,fin); if(memcmp(tag,HEADER_TAG,HEADER_LEN)!=0){ fclose(fin); show_status(w,"Not encrypted",theme); return -2;}
    uint64_t orig_size; fread(&orig_size,sizeof(orig_size),1,fin);
    char tmp[1024]; snprintf(tmp,sizeof(tmp),"%s.des.tmp",path);
    FILE *fout=fopen(tmp,"wb"); if(!fout){ fclose(fin); show_status(w,"Cannot create temp file",theme); return -1;}
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); EVP_DecryptInit_ex(ctx,EVP_des_ecb(),NULL,key,NULL);
    unsigned char inbuf[BUF_SZ],outbuf[BUF_SZ+EVP_MAX_BLOCK_LENGTH]; int outlen=0; size_t n; uint64_t written=0;
    while((n=fread(inbuf,1,sizeof(inbuf),fin))>0){
        EVP_DecryptUpdate(ctx,outbuf,&outlen,inbuf,(int)n);
        uint64_t remain=orig_size>written? orig_size-written:0;
        uint64_t tow=remain>(uint64_t)outlen? (uint64_t)outlen:remain;
        if(tow>0) fwrite(outbuf,1,(size_t)tow,fout); written+=tow; draw_progress(w,(double)written/(double)orig_size,theme);
        if(written>=orig_size) break;
    }
    EVP_DecryptFinal_ex(ctx,outbuf,&outlen); if(written<orig_size){ uint64_t remain=orig_size-written; if(remain>0) fwrite(outbuf,1,(size_t)remain,fout);}
    EVP_CIPHER_CTX_free(ctx); fclose(fin); fclose(fout); remove(path); rename(tmp,path);
    sound_alert_ok(); show_status(w,"Decryption successful",theme); return 0;
}

/* UI prompt */
static void prompt_and_do(WINDOW *owner,int is_encrypt,theme_t theme){
    int maxy=LINES,maxx=COLS,winh=12,winw=(maxx>80?80:maxx-8),starty=(maxy-winh)/2,startx=(maxx-winw)/2;
    WINDOW *w=newwin(winh,winw,starty,startx); keypad(w,TRUE); box(w,0,0);
    wbkgd(w,(theme==THEME_T1?COLOR_PAIR(1):COLOR_PAIR(4)));
    mvwprintw(w,1,2,is_encrypt?"ENCRYPT — file + 8-char key":"DECRYPT — file + 8-char key");
    mvwprintw(w,3,2,"File path: "); mvwprintw(w,5,2,"Key (8 chars, hidden): "); wrefresh(w);

    echo(); curs_set(1); char pathbuf[512]={0}; mvwgetnstr(w,3,13,pathbuf,sizeof(pathbuf)-1); noecho();
    char keybuf[KEY_LEN+1]={0}; curs_set(1); noecho(); mvwgetnstr(w,5,25,keybuf,KEY_LEN); echo(); curs_set(0);
    if(strlen(keybuf)<KEY_LEN){ show_status(w,"Key must be 8 chars",theme); delwin(w); napms(900); return; }
    unsigned char evp_key[KEY_LEN]; memcpy(evp_key,keybuf,KEY_LEN);
    show_status(w,is_encrypt?"Starting encryption...":"Starting decryption...",theme);
    if(is_encrypt) encrypt_path_with_key(w,pathbuf,evp_key,theme);
    else decrypt_path_with_key(w,pathbuf,evp_key,theme);
    mvwprintw(w,winh-2,2,"Press any key to continue..."); wrefresh(w); wgetch(w); delwin(w);
}

/* Init colors */
static void init_theme_colors(void){
    start_color(); use_default_colors();
    init_pair(1,COLOR_WHITE,COLOR_BLUE);    // bg blue
    init_pair(2,COLOR_YELLOW,COLOR_BLUE);   // text accent
    init_pair(3,COLOR_BLACK,COLOR_YELLOW);  // progress fill
    init_pair(4,COLOR_BLACK,COLOR_WHITE);   // alt bg
    init_pair(5,COLOR_YELLOW,COLOR_BLACK);  // alt text
    init_pair(6,COLOR_WHITE,COLOR_BLUE);    // alt progress
    init_pair(7,COLOR_YELLOW,COLOR_BLUE);   // golden title & stars
}

int main(void){
    OSSL_PROVIDER *legacy=load_legacy_provider();
    initscr(); cbreak(); noecho(); keypad(stdscr,TRUE); nodelay(stdscr,TRUE); curs_set(0);
    init_theme_colors(); srand(time(NULL));
    for(int i=0;i<MAX_STARS;i++){ stars[i].x=rand()%COLS; stars[i].y=rand()%LINES; stars[i].speed=1+rand()%3; stars[i].counter=0; }
    theme_t theme=THEME_T1; int title_pos=4,dir=1;

    for(;;){
        int maxy=LINES,maxx=COLS; erase();

        // backdrop first
        attron(theme==THEME_T1?COLOR_PAIR(1):COLOR_PAIR(4));
        for(int r=0;r<maxy;r++) mvhline(r,0,' ',maxx);
        attroff(theme==THEME_T1?COLOR_PAIR(1):COLOR_PAIR(4));

        // stars on top
        attron(COLOR_PAIR(7));
        for(int i=0;i<MAX_STARS;i++){
            stars[i].counter++;
            if(stars[i].counter>=stars[i].speed){ stars[i].x++; stars[i].counter=0; if(stars[i].x>=maxx){ stars[i].x=0; stars[i].y=rand()%maxy; } }
            mvaddch(stars[i].y,stars[i].x,'*');
        }
        attroff(COLOR_PAIR(7));

        // golden title
        const char *title=" █ DES FILE CRYPTO — GOLDEN THEME █ ";
        int tlen=strlen(title), min_x=2, max_x=maxx-tlen-4;
        if(max_x<min_x) max_x=min_x;
        if(title_pos<min_x) title_pos=min_x;
        if(title_pos>max_x) title_pos=max_x;
        attron(COLOR_PAIR(7)|A_BOLD); mvprintw(2,title_pos,"%s",title); attroff(COLOR_PAIR(7)|A_BOLD);

        // menu
        attron(A_BOLD);
        mvprintw(6,(maxx/2)-12,"1) Encrypt file");
        mvprintw(8,(maxx/2)-12,"2) Decrypt file");
        mvprintw(10,(maxx/2)-12,"3) Toggle theme");
        mvprintw(12,(maxx/2)-12,"4) Exit");
        attroff(A_BOLD);

        draw_clock(); refresh();

        // animate title
        title_pos+=dir; if(title_pos>=max_x) dir=-1; if(title_pos<=min_x) dir=1;

        int ch=getch();
        if(ch==ERR){ usleep(70000); continue; }
        if(ch=='4') break;
        else if(ch=='3'){ theme=(theme==THEME_T1)?THEME_T1_ALT:THEME_T1; show_status(stdscr,theme==THEME_T1?"Theme: GOLDEN":"Theme: ALT",theme); napms(500); continue; }
        else if(ch=='1'){ nodelay(stdscr,FALSE); prompt_and_do(stdscr,1,theme); nodelay(stdscr,TRUE); }
        else if(ch=='2'){ nodelay(stdscr,FALSE); prompt_and_do(stdscr,0,theme); nodelay(stdscr,TRUE); }
    }

    endwin();
    if(legacy) OSSL_PROVIDER_unload(legacy);
    EVP_cleanup(); ERR_free_strings();
    return 0;
}
