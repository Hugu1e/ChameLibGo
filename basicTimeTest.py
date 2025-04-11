import os

done = [
    # "CH_CDK_2017",
    # "CH_ET_BC_CDK_2017",
    # "CH_ET_KOG_CDK_2017",
    # "CH_FS_ECC_CCT_2024",

    # "CH_KEF_CZK_2004",
    # "CH_KEF_DL_CZT_2011",
    # "CH_KEF_DLP_LLA_2012",
    # "CH_KEF_MH_RSA_F_AM_2004",
    # "CH_KEF_MH_RSANN_F_AM_2004",
    # "CHET_RSA_CDK_2017",
    # "CH_KEF_MH_SDH_DL_AM_2004",
    # "CH_KEF_NoMH_AM_2004",
    # "CR_CH_DSS_2020",
    # "FCR_CH_PreQA_DKS_2020",
    # "MCH_CDK_2017",

    # "IB_CH_KEF_CZS_2014",
    # "IB_CH_MD_LSX_2022",
    # "IB_CH_ZSS_S1_2003",
    # "IB_CH_ZSS_S2_2003",
    # "ID_B_CollRes_XSL_2021",

    # "MAPCH_ZLW_2021",
    # "PCHBA_TLL_2020",
    # "PCH_DSS_2019",
    # "RPCH_TMM_2022",

    # "RPCH_XNM_2021",
    # "DPCH_MXN_2022"
]

rep_times = 500

for scheme_type in ["CH", "IBCH", "PBCH"]:
    for dirpath, dirnames, filenames in os.walk(f'./scheme/{scheme_type}'):
        if dirpath == f'./scheme/{scheme_type}': continue
        scheme_name = dirpath.split('/')[-1]
        if scheme_name in done: continue
        print(f"Test {dirpath}:")
        print("--------------------------------------------------------------------------")
        open(f'./testResult/{scheme_name}.txt', 'w')
        os.system(f'cd {dirpath} && go test -timeout 3600000s -repeat {rep_times}')
