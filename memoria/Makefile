DOCUMENTS = tfg


compile:
	@echo "Generating pdfs..."
	@for doc in $(DOCUMENTS); do \
		pdflatex $$doc.tex >> /dev/null; \
		echo "Generated: Index for $$doc.pdf"; \
		pdflatex $$doc.tex >> /dev/null; \
		echo "Generated: $$doc.pdf"; \
		done
	@make clean >> /dev/null
	@echo "All done."

.PHONY: clean

clean:
	@echo "Borrando archivos generados en compilación TeX..."
	@find . -type f -name 'tfg.a*' -exec rm {} +
	@find . -type f -name 'tfg.g*' -exec rm {} +
	@find . -type f -name 'tfg.i*' -exec rm {} +
	@find . -type f -name 'tfg.l*' -exec rm {} +
	@find . -type f -name 'tfg.m*' -exec rm {} +
	@find . -type f -name 'tfg.o*' -exec rm {} +
	@find . -type f -name 'tfg.toc' -exec rm {} +
	@find . -type f -name 'tfg.x*' -exec rm {} +
	@echo "Borrado completado."