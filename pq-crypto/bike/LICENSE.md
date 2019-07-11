/******************************************************************************
* Additional implementation of "BIKE: Bit Flipping Key Encapsulation". 
* This package is an "additional optimized" implementation of BIKE{1/2/3}, 
* of the BIKE submission to csrc.nist.gov/projects/post-quantum-cryptography.
* by: 
* Nicolas Aragon, University of Limoges, France
* Paulo S. L. M. Barreto, University of Washington Tacoma, USA
* Slim Bettaieb, Worldline, France
* Loïc Bidoux, Worldline, France
* Olivier Blazy, University of Limoges, France
* Jean-Christophe Deneuville, INSA-CVL Bourges and University of Limoges, France
* Philippe Gaborit, University of Limoges, France
* Shay Gueron, University of Haifa, and Amazon Web Services, Israel
* Tim Güneysu, Ruhr-Universität, Ruhr-Universitat Bochum, and DFKI, Germany, 
* Carlos Aguilar Melchor, University of Toulouse, France
* Rafael Misoczki, Intel Corporation, USA  
* Edoardo Persichetti, Florida Atlantic University, USA 
* Nicolas Sendrier, INRIA, France
* Jean-Pierre Tillich, INRIA, France
* Gilles Zémor, IMB, University of Bordeaux, France
*
* The package offers AVX2 and AVX512 implementations, and can be compiled  
* with/without constant time components. 
* The optimizations are based on the description developed in the paper: 
* N. Drucker, S. Gueron, 
* "A toolbox for software optimization of QC-MDPC code-based cryptosystems", 
* ePrint (2017).
* The decoder (in decoder/decoder.c) algorithm is the algorithm included in
* the early submission of CAKE (due to N. Sandrier and R Misoczki).
*
* Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
* Written by Nir Drucker and Shay Gueron, 
* AWS Cryptographic Algorithms Group
* (ndrucker@amazon.com, gueron@amazon.com)
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
* http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
******************************************************************************/
