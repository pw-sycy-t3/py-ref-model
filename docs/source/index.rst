AEGIS-ZERO Reference Model
===========================

Python reference model for the AEGIS-ZERO hardware firewall: a two-stage
packet classification pipeline combining a Bloom filter pre-filter
(Layer 1, :mod:`bloom_filter`) with a 3-ary Cuckoo hash rule table
(Layer 2, :mod:`cuckoo_hash`).

.. autosummary::
   :toctree: generated
   :recursive:

   common
   bloom_filter
   cuckoo_hash
   aegis_pipeline
   main
