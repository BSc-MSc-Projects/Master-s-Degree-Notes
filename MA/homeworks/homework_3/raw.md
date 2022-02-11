#Introduzione ed obiettivi
Il seguente documento riporta i passi seguiti per l'analisi del file eseguibile __hw3.exe__. Il file è stato analizzato mediante l'uso dei tools Ghdira ed OllyDbg, gli obiettivi dell'analisi sono molteplici:

- trovare il codice di sblocco che rende funzionante l'applicazione
- raccogliere infomrazioni riguardo l'eseguibile

# Ricerca del WinMain
La ricerca del WinMain, che è il punto d'ingresso per le applicazioni Windows basate su GUI, è avvenuta mediante Ghidra, individuando nel codice dove avviene il __Messsage Loop__. Consultando le funzioni importate dalla DLL User, si può evincere che, ad esempio, la API GetMessageA viene chiamata una sola volta, nella funzione _FUN\_004024e0_ e tale funzione è quindi la __Win Main__, che è stata riportata sia in Ghidra che in OllyDbg (indirizzo 004024e0), definiamo poi anche la Win Proc, ad indirizzo 00401de0. È stata quindi analizzata la WinProc, per vedere quali tipi di messaggi venivano gestiti.

# Definizione della struttura dati
Le informazioni riportate di seguito riferiscono il report scorso, in quanto la struttura del codice è molto simile. Per definire la struttura dati quindi, è stata aperta la funzione a 401830, inizializza la struttura di dati. Sono stati inseriti i campi
Tutti i campi sono stati definiti guardando i riferienti dentro Ghidra e riferendo l'homework precedente

## Analisi preliminare della WinProc
Come accadeva anche nel precedente file eseguibile analizzato, la WinProc gestisce fra i messaggi:
- WM\_CREATE, con codice 1;
- WM\_DESTROY, con codice 2;
- WM\_MESSAGE
...

Nella gestione della WM\_CREATE, viene inserito un dato definito dall'utente mediante la chiamata alla __SetWindowLong__, tale dato è lParam che a sua volta è stato impostato al valore di param\_4.
lParam viene poi usato spiazzandosi ad offset 168, per copiare gli indirizzi di tutte le finestre create, quindi è probabile che contenga una struct. Occorre capire dove viene inizializzata tale struct, che in questo blocco di codice viene acceduta fino ad un offset limite di 188 byte, quindi è ragionevole assegnarle tale dimensione iniziale.

## Inizalizzazione della struttura dati
All'interno del WinMain, c'è la funzione _FUN\_00401830_ che inizializza la struttura dati, che viene ritornata ed il cui indirizzo viene assegnato al parametro lpParam. Nella funzione di inizializzazione, denominata come init\_ds:

- l'indirizzo di ritorno è quello della variabile _DAT\_00407020_, che quindi è la struttura dati e viene rinominata come app\_ds
- viene quindi creata all'interno di Ghidra tale struttura dati, definendone i campi iniziali ed una taglia di 188 byte

Nella funzione di inizializzazione:
- si passa come parametro la variabile globale _DAT\_004040e0_, a sua volta assegnata al campo ad offset (vedi struct) della struct.

## Analisi dell'uso della struct nella WinProc
Nella WinProc, la struttura dati viene accceduta a partire da offset 168 e fino a 188, per inserire 6 handles, quindi tale campo è un array di handles (HWND). Abbiamo poi, sempre nella gestione del WM\_CREATE, l'inizializzazione del timer, per poi passare alla chiamata della __SetTimer__, che mette il valore di ritorno nel campo della struttura ad offset 8.

Nella TimerProc, si effettua una chiamata al campo param\_1, che a sua volta era l'indirizzo di _DAT\_004040e0_, quindi le istruzioni che seguono quel dato sono istruzioni che vanno disassemblate.

# Analisi della funzione chiamata dalla TimerProc
All'interno, tale funzione presenta diverse zone che Ghidra non è riuscito a risolvere, in quanto sono stati applicati meccanismi anti-disassembing: in paritcolare, vi sono divese istruzioni di JUMP condizionale, che però sono sempre verificate, in quanto si accede ad un dato del segmento .bss che non viene mai scritto ma solo letto, e quindi non può che essere pari a 0. In seguito alla risoluzione dei problemi, è possibile consultare un codice decompilato molto più leggibile, dove si individua la chiamata alla _GetDlgItemTextA_, ovvero si prende il contenuto testuale dell'handle che contiene il codice di sblocco.
Tale contenuto viene inserito nella variabile acStack42, che è un vettore di 30 caratteri. Dalla funzione non è chiaro come viene verificato se il codice inserito dall'utente sia quello corretto, quindi è stato aperto il programma in OllyDbg, procedendo sia con analisi statica che dinamica.

------------------------------ TUTTO QUELLO CHE STA SOPRA DERIVA DALL'ESPERIENZA --------------------------------------------------

# Lancio iniziale del programma
Nel momento in cui si cerca di debuggare il programma mediante l'utilizzo di OllyDbg, facendo partire con f9 il debugger termina immediatamente l'esecuzione. Quindi, sono presenti dei meccanismi anti-debugging all'interno del codice. Il primo passo seguito è stato quello di cercare e bypassare tali meccanismi

## Ricerca dei meccanismi anti-debugging
Per scoprire quali meccanismi anti-debugging sono stati introdotti, è stato utilizzato Ghidra, provando a fare la ricerca di API che rivelano la presenza di un debugger attivo. Troviamo, fra le API della DDL Kernel32, la funzione _IsDebuggerPresent_, chiamata all'interno della funzione _FUN\_OO4024a0_, la cui prima istruzione è all'indirizzo di memoria 004024a0. Qui, a seguito delle chiamata, viene fatto un test su EAX e nel caso in cui il valore di tale registro sia diverso da 0, si esce dal programma. È stata quindi inserita una patch nell'eseguibile, sostituendo l'istruzione XOR EAX, EAX (seguita da NOP) al posto della CALL alla API ed è stato generato tramite OllyDbg il nuovo file eseguibile patchato.
Una volta terminata la patch dell'eseguibile, il debugger riesce ad arrivare nella funzione, dove è stata effetutata tale patch, (ed è stato messo un breakpoint) ed una volta completata ritornare nel WinMain. Il problema è che all'interno della funzione vi è una chiamata alla API _ShowWindow_, che dovrebbe quindi mostrare la finestra, ma ciò non accade. Inoltre, una volta terminata l'esecuzione della'API, l'ultimo errore registrato dal debugger è __INVALID_WINDOW_HANDLE__.

Impostando un breakpoint sulla WinProc, si nota che il programma entra prima lì dentro e poi nella funzione che verifica la presenza del debugger. Qui, vi è la CALL alla funzione __FUN_00401dc__, dove si manipola la struttura dati PEB:

- si accede ad offset 0x30, spiazzandosi poi ad offset 2;
- qui, vi è il campo _BeingDebugged_, pari a 0 se non c'è debugger.
- viene caricato questo campo ibn EDX e ne viene fatto l'AND logico con 0x7

Quindi:

- se EDX = 0 : 0000 & 0111 = 0000
- se EDX = 1 : 0001 & 0111 = 0001

(E8 A1FFFFFF)

Mandando avanti il debugger, sembra comparire la finestra alla fine della creazione, ma dopo alcuni secondi il programma va im crash. Aprendo il programma, appare un messaggio di errore "Internal Error". Dentro Ghidra quindi, è stata cercata fra le stringhe di programma, per verificare quando viene usata.
La stringa esiste, ma non sembra presentare dei riferimenti che potrebbero essere stati nascosti con dei meccanismi anti-disassembing. Tornando al WinMain, all'interno della init\_ds, c'è una chiamata a funzione, la __FUN_004016f0__ che se deassembata, mostra una tecnica anti-disassembling:
vi è difatti la sequenza di istruzioni macchina __eb ff c0 48__ che è una delle possibili realizzazioni di disassembing impossibile. Per risolverlo, è stato necessario dissassemblare saltando ogni volta quella sequenza di istruzioni, che sono state sostituite con una serie di NOP. Dal decompilato, si può evnicere quindi che:
- viene scritta nella variabile automatica local\_2d, rinominata local\_str la stringa "kernel32.dll"
- chiamta la LoadLibraryA, quindi caricata la libreria __kernel3.dll__ dinamicamente
- viene poi messa nello stesso array di prima la stringa "OutputDebugStringA"
- viene infine chiamta la __GetProcAddress__: questa API restituisce l'indirizzo della funzione _OutputDebugString_

Tornando alla init\_ds, viene assegnata ad una variabile globale. (Andando nel segmento .bss, si nota che altre variabili globali vengono accedute in scrittura, la cui posizione è proprio sotto la struttura dati definita in precedenza. Siccome tali variabili vengono usate in funzioni a loro volta riferite dalla WinMain o dalla WinProc, è probabile che siano a loro volta parte della struttura dati, quindi sono state incluse all'interno.)

Mouovendosi nell'analisi della TimerProc, si nota che all'interno del blocco di codice che verifica il tempo corrente non sia pari a 0, c'è una chiamata alla funzione __FUN_004042a0__: aprendola, anche tale funzione presenta dei meccanismi di anti-debug, in particolare delle CALL all'interno dei istruzioni (?? spiega meglio)

Facendo una patch in OllyDbg, è stato possibile risolvere il problema legato all'Internal Error che veniva mostrato, andando a sostituire con delle NOP la chiamata alla funzione. Effettivamente ora il programma si apre, ma detro OllyDbg, se si fa partire normalmente con f9 ritorna a crashare poco prima di mostrare la finestra.

Proseguendo l'analisi, è evidente che il problema avviene in uno dei blocchi per la gestione dei comandi ricevuti. Quindi, sono stati impostati diversi breakpoints per vedere se tali blocchi venivano eseguiti

### Blocco per il codice 5 (WM\_PIANT ??)
Nel blocco del WM\_PAINT, alla fine delle operazioni per ridisegnare la finestra, c'è la CALL alla funzione __FUN_00404000__, che è stata analizzata usando OllyDbg. La funzione prende molti parametri, ma sia le istruzioni assembly che il codice de-compilato non sembrano aiutare nel capire cosa fa.
Viene caricata la stringa "%s%s%s....", seguita dalla CALL alla API __OutputDebugStringA__, precedentemente caricata, quindi un ulteriore meccanismo anti-debugging, il tutto all'indirizzo 40504A. Per risolvere, sono state messe delle NOP sulla chiamata API.

__Al me del futuro: non so come ha fatto il te del passato, ma ha risolto le cose. Il file buono è "patched-3.2", lascerò a te l'incombenza di capire che cazzo hai modificato per farlo funzionare, che io mo devo trova il codice di sblocco e non c'ho tempo. Tante care cose, ciao__

# Ricerca del codice di sblocco
Viene messo un breakpoint su 4040e0, punto in cui parte la routine registrata per la TimerProc, si fa partire l'applicazione e si inserisce un codice a caso per vedere il comportamento.

Funzione 40500c, dove c'è un confronto fra caratteri:
\ANCA]G?0?

Sono 8 caratteri.

x\_1 xor 'char' = 0C

1° carattere
1111 	1110
1111 	0010  = F2 ò
-------------
0000 	1100


2° carattere
1111 	1111
1010 	0101 = A5  ¥
-------------
0101 	1010

3° carattere
1111 	1111
1001 	1110 = 9E ž
-------------
0110 	0001

4° carattere   SBAGLIATO
(ò)

0110 	0001

1111 	1111
0011 	1111 = 3F ?
-------------
1100 	0000


5° carattere
0101 	1101
0111 	0011 = 73 s
-------------
0010 	1110


6° carattere

0100 	0111
0101 	0100 = 54 T
-------------
0001 	0011

7° carattere
0101 	1111
0011	0000 = 30 0
-------------
0000 	1101

8° carattere
0100 	1111
0011 	1111 = 3F ?
-------------
0111 	0000

9° carattere 
0011 	1111
0010 	0001 = 21 !
------------
0001 	1110


Il codice non è corretto, deve spegnere la versione non patchata del binario.

La 404040 contiene la chiamata alla __ExitWindowEx__, viene chiamata da dentro il codice chiamato a sua volta dalla TimerProc. Incrocio delle istruzioni di OllyDbg con quelle di Ghidra. Nuovo conto:

1° carattere
0011 	1111
0011 	0011 = 33 = 3
-------------
0000 	1100 

2° carattere (NO)
0010 	1000
0111 	0010 = 72 = r
-------------
0101 	1010

3° carattere

0010 	1111 
0100 	1110 = 4E = N
-------------
0110 	0001 

4° carattere (NO)
1010 	0101
1010 	1001 = 65 = e
------------- 
1100 	0000

5° carattere
0101 	1101
0111 	0011 = 73 = s
-------------
0010 	1110 

6° carattere


T0!?





